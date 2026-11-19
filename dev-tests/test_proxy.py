#!/usr/bin/env python3
"""
End-to-end tests for the proxy core, run on a desktop JVM.

An independent Python implementation plays both sides:
  * a Telegram client that talks to the proxy with a secret (MTProto obfuscated2), and
  * a mock Telegram datacenter reachable over WebSocket (plain or TLS) and plain TCP.

Usage: python3 test_proxy.py <dir with compiled classes>
Needs: java, python3, the 'cryptography' package.
"""
import base64
import datetime
import hashlib
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID

WS_GUID = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
TAG_ABR, TAG_INT, TAG_PAD = b'\xef' * 4, b'\xee' * 4, b'\xdd' * 4
RESERVED = {b'HEAD', b'POST', b'GET ', b'\xee' * 4, b'\xdd' * 4, b'\x16\x03\x01\x02', b'OPTI'}


def aes_ctr(key, iv):
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


def sha256(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError('peer closed after %d of %d bytes' % (len(buf), n))
        buf += chunk
    return buf


def read_until(sock, marker):
    buf = b''
    while marker not in buf:
        chunk = sock.recv(1)
        if not chunk:
            raise EOFError('closed while reading headers')
        buf += chunk
    return buf


# ---- MTProto transport framing ------------------------------------------------------------------

def packet(tag, payload):
    if tag == TAG_ABR:
        assert len(payload) % 4 == 0
        n = len(payload) // 4
        return (bytes([n]) if n < 0x7f else b'\x7f' + n.to_bytes(3, 'little')) + payload
    return struct.pack('<I', len(payload)) + payload


class Parser:
    def __init__(self, tag):
        self.tag = tag
        self.buf = b''

    def feed(self, data):
        self.buf += data
        out = []
        while True:
            p = self._one()
            if p is None:
                return out
            out.append(p)

    def _one(self):
        b = self.buf
        if not b:
            return None
        if self.tag == TAG_ABR:
            first = b[0]
            if first in (0x7f, 0xff):
                if len(b) < 4:
                    return None
                n, h = int.from_bytes(b[1:4], 'little') * 4, 4
            else:
                n, h = (first & 0x7f) * 4, 1
        else:
            if len(b) < 4:
                return None
            n, h = struct.unpack('<I', b[:4])[0] & 0x7fffffff, 4
        if len(b) < h + n:
            return None
        self.buf = b[h + n:]
        return b[h:h + n]


# ---- Telegram client (talks to the proxy with a secret) -----------------------------------------

def make_client_init(secret, tag, dc_idx):
    while True:
        rnd = bytearray(os.urandom(64))
        if rnd[0] == 0xef or bytes(rnd[:4]) in RESERVED or rnd[4:8] == b'\0\0\0\0':
            continue
        break
    prekey_iv = bytes(rnd[8:56])
    enc = aes_ctr(sha256(prekey_iv[:32], secret), prekey_iv[32:48])
    rnd[56:64] = tag + struct.pack('<h', dc_idx) + os.urandom(2)
    encrypted = enc.update(bytes(rnd))
    init = bytes(rnd[:56]) + encrypted[56:64]
    rev = prekey_iv[::-1]
    dec = aes_ctr(sha256(rev[:32], secret), rev[32:48])
    return init, enc, dec


def run_client(port, secret, tag, dc_idx, payloads, cuts=None, timeout=10):
    """Send packets through the proxy; expect b'RESP:' + payload for each one back."""
    init, enc, dec = make_client_init(secret, tag, dc_idx)
    s = socket.create_connection(('127.0.0.1', port), timeout=timeout)
    try:
        s.sendall(init)
        stream = enc.update(b''.join(packet(tag, p) for p in payloads))
        if cuts:
            prev = 0
            for c in list(cuts) + [len(stream)]:
                s.sendall(stream[prev:c])
                prev = c
                time.sleep(0.05)
        else:
            s.sendall(stream)
        expected = b''.join(b'RESP:' + p for p in payloads)
        got = dec.update(recv_exact(s, len(expected)))
        assert got == expected, 'reply mismatch (got %d bytes, want %d)' % (len(got), len(expected))
    finally:
        s.close()


def expect_closed(port, data, timeout=5):
    s = socket.create_connection(('127.0.0.1', port), timeout=timeout)
    try:
        s.sendall(data)
        assert s.recv(1) == b'', 'proxy should have closed the connection'
    finally:
        s.close()


# ---- WebSocket frames ---------------------------------------------------------------------------

def ws_frame(op, payload, fin=True):
    b0 = (0x80 if fin else 0) | op
    n = len(payload)
    if n < 126:
        hdr = bytes([b0, n])
    elif n < 65536:
        hdr = bytes([b0, 126]) + struct.pack('>H', n)
    else:
        hdr = bytes([b0, 127]) + struct.pack('>Q', n)
    return hdr + payload


def ws_read_frame(sock):
    h = recv_exact(sock, 2)
    fin, op, masked, ln = h[0] & 0x80, h[0] & 0x0f, h[1] & 0x80, h[1] & 0x7f
    if ln == 126:
        ln = struct.unpack('>H', recv_exact(sock, 2))[0]
    elif ln == 127:
        ln = struct.unpack('>Q', recv_exact(sock, 8))[0]
    mask = recv_exact(sock, 4) if masked else None
    payload = recv_exact(sock, ln)
    if masked:
        m = (mask * (ln // 4 + 1))[:ln]
        payload = (int.from_bytes(payload, 'big') ^ int.from_bytes(m, 'big')).to_bytes(ln, 'big') if ln else b''
    return bool(fin), op, bool(masked), payload


# ---- mock Telegram datacenter -------------------------------------------------------------------

class MockDC:
    def __init__(self, tls_ctx=None):
        self.tls_ctx = tls_ctx
        self.mode = 'ok'          # ok | redirect
        self.send_ping = False
        self.fragment_replies = False
        self.ws_log = []          # one dict per accepted WebSocket upgrade
        self.pongs = []
        self.snis = []
        self.errors = []
        self.ws_count = 0
        self.tcp_log = []
        self.ws_listen = self._listen()
        self.tcp_listen = self._listen()
        self.ws_port = self.ws_listen.getsockname()[1]
        self.tcp_port = self.tcp_listen.getsockname()[1]
        if tls_ctx is not None:
            tls_ctx.sni_callback = lambda sock, name, ctx: self.snis.append(name)
        threading.Thread(target=self._accept, args=(self.ws_listen, self._ws_conn), daemon=True).start()
        threading.Thread(target=self._accept, args=(self.tcp_listen, self._tcp_conn), daemon=True).start()

    @staticmethod
    def _listen():
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        s.listen(64)
        return s

    def _accept(self, listener, handler):
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=self._guard, args=(handler, conn), daemon=True).start()

    def _guard(self, handler, conn):
        try:
            handler(conn)
        except (EOFError, ConnectionError, ssl.SSLError, OSError):
            pass
        except Exception:
            self.errors.append(traceback.format_exc())
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _crypto(init):
        dec = aes_ctr(init[8:40], init[40:56])
        plain_init = dec.update(init)
        rev = init[8:56][::-1]
        enc = aes_ctr(rev[:32], rev[32:48])
        return dec, enc, plain_init[56:60], struct.unpack('<h', plain_init[60:62])[0]

    # WebSocket side
    def _ws_message(self, conn):
        while True:
            fin, op, masked, payload = ws_read_frame(conn)
            if not masked:
                self.errors.append('client frame was not masked')
            if op == 0x8:
                return None
            if op == 0x9:
                conn.sendall(ws_frame(0xA, payload))
                continue
            if op == 0xA:
                self.pongs.append(payload)
                continue
            assert op == 0x2 and fin, 'unexpected frame op=%x fin=%s' % (op, fin)
            return payload

    def _ws_conn(self, conn):
        if self.tls_ctx is not None:
            conn = self.tls_ctx.wrap_socket(conn, server_side=True)
        req = read_until(conn, b'\r\n\r\n').decode('latin1').split('\r\n')
        hdr = {}
        for line in req[1:]:
            if ': ' in line:
                k, v = line.split(': ', 1)
                hdr[k.lower()] = v
        rec = {'path': req[0].split(' ')[1], 'host': hdr.get('host'),
               'proto': hdr.get('sec-websocket-protocol'), 'ver': hdr.get('sec-websocket-version')}
        self.ws_log.append(rec)
        if self.mode == 'redirect':
            conn.sendall(b'HTTP/1.1 302 Found\r\nLocation: https://example.org/\r\nContent-Length: 0\r\n\r\n')
            return
        accept = base64.b64encode(hashlib.sha1(hdr['sec-websocket-key'].encode() + WS_GUID).digest())
        conn.sendall(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                     b'Sec-WebSocket-Accept: ' + accept + b'\r\nSec-WebSocket-Protocol: binary\r\n\r\n')
        self.ws_count += 1
        init = self._ws_message(conn)
        if init is None:
            return
        assert len(init) == 64, 'first WS message must be the 64-byte init, got %d' % len(init)
        dec, enc, tag, dc_idx = self._crypto(init)
        rec.update(tag=tag, dc_idx=dc_idx, used=True)
        if self.send_ping:
            conn.sendall(ws_frame(0x9, b'hi'))
        while True:
            msg = self._ws_message(conn)
            if msg is None:
                return
            p = Parser(tag)
            payloads = p.feed(dec.update(msg))
            if len(payloads) != 1 or p.buf:
                self.errors.append('WS message is not exactly one transport packet (%d packets, %d left over)'
                                   % (len(payloads), len(p.buf)))
                return
            reply = enc.update(b'RESP:' + payloads[0])
            if self.fragment_replies and len(reply) > 8:
                k = len(reply) // 2
                conn.sendall(ws_frame(0x2, reply[:k], fin=False) + ws_frame(0x0, reply[k:]))
            else:
                conn.sendall(ws_frame(0x2, reply))

    # plain TCP side
    def _tcp_conn(self, conn):
        init = recv_exact(conn, 64)
        dec, enc, tag, dc_idx = self._crypto(init)
        self.tcp_log.append({'tag': tag, 'dc_idx': dc_idx})
        parser = Parser(tag)
        while True:
            data = conn.recv(65536)
            if not data:
                return
            for payload in parser.feed(dec.update(data)):
                conn.sendall(enc.update(b'RESP:' + payload))


# ---- harness ------------------------------------------------------------------------------------

def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Proxy:
    def __init__(self, classes, secret, args):
        self.port = free_port()
        self.lines = []
        cmd = ['java', '-cp', classes, 'dev.personal.tgws.core.CliMain',
               '--port', str(self.port), '--secret', secret.hex(), '-v'] + args
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        ready = threading.Event()

        def pump():
            for line in self.proc.stdout:
                line = line.rstrip()
                self.lines.append(line)
                if line == 'LISTENING':
                    ready.set()

        threading.Thread(target=pump, daemon=True).start()
        if not ready.wait(20):
            raise RuntimeError('proxy did not start:\n' + '\n'.join(self.lines))

    def log(self):
        return '\n'.join(self.lines)

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


results = []


def check(name, fn):
    try:
        fn()
        results.append((name, True, ''))
        print('PASS  ' + name)
    except Exception:
        results.append((name, False, traceback.format_exc()))
        print('FAIL  ' + name + '\n' + traceback.format_exc())


def wait_for(cond, seconds=5):
    end = time.time() + seconds
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


def make_cert(dns_names, directory):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_names[0])])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in dns_names]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path = os.path.join(directory, dns_names[0] + '.crt')
    key_path = os.path.join(directory, dns_names[0] + '.key')
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, 'wb') as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    return cert_path, ctx


def main():
    classes = sys.argv[1]
    secret = os.urandom(16)
    tmp = tempfile.mkdtemp()

    # ================= plain WebSocket mock =================
    dc = MockDC()
    proxy = Proxy(classes, secret, [
        '--ws-ip', '2:127.0.0.1', '--ws-ip', '4:127.0.0.1', '--ws-port', str(dc.ws_port), '--no-tls',
        '--tcp-ip', '2:127.0.0.1', '--tcp-ip', '4:127.0.0.1', '--tcp-ip', '5:127.0.0.1',
        '--tcp-port', str(dc.tcp_port), '--pool', '2'])
    try:
        def pool_warmup():
            assert wait_for(lambda: dc.ws_count >= 2), 'pool did not pre-connect (ws_count=%d)' % dc.ws_count
        check('pool warms up idle WebSocket connections', pool_warmup)
        time.sleep(0.3)

        def abridged_coalesced():
            run_client(proxy.port, secret, TAG_ABR, 2, [b'A' * 16, b'B' * 40, b'C' * 4])
            assert any(r['host'] == 'kws2.web.telegram.org' for r in dc.ws_log), dc.ws_log
            r = [r for r in dc.ws_log if r.get('used')][-1]
            assert r['path'] == '/apiws' and r['proto'] == 'binary' and r['ver'] == '13', r
            assert r['dc_idx'] == 2 and r['tag'] == TAG_ABR, r
            assert 'DC2 -> WS (pool)' in proxy.log(), proxy.log()
        check('abridged, 3 coalesced packets -> one WS message each, pool hit', abridged_coalesced)

        def intermediate_split():
            payloads = [b'x' * 100, b'y' * 28]
            total = len(packet(TAG_INT, payloads[0]))
            run_client(proxy.port, secret, TAG_INT, 2, payloads, cuts=[7, total + 2])
        check('intermediate, packets cut mid-header and mid-packet', intermediate_split)

        def padded_media():
            run_client(proxy.port, secret, TAG_PAD, -4, [b'm' * 33, b'n' * 5])
            recs = [r for r in dc.ws_log if r['host'] == 'kws4-1.web.telegram.org']
            assert recs, dc.ws_log
            used = [r for r in recs if r.get('used')]
            assert used and used[-1]['dc_idx'] == -4 and used[-1]['tag'] == TAG_PAD, recs
        check('padded intermediate, media DC4 -> kws4-1 host, negative dc id kept', padded_media)

        def big_packet():
            run_client(proxy.port, secret, TAG_INT, 2, [os.urandom(200_000)])
        check('200 KB packet (64-bit WS length), reply reassembled', big_packet)

        def ping_pong():
            dc.send_ping = True
            try:
                run_client(proxy.port, secret, TAG_ABR, 2, [b'p' * 8])
                assert wait_for(lambda: b'hi' in dc.pongs), 'no pong received'
            finally:
                dc.send_ping = False
        check('server ping is answered with a pong', ping_pong)

        def fragmented():
            dc.fragment_replies = True
            try:
                run_client(proxy.port, secret, TAG_ABR, 2, [b'f' * 64])
            finally:
                dc.fragment_replies = False
        check('fragmented WS reply is reassembled', fragmented)

        def tcp_fallback_no_ws_route():
            before = len(dc.ws_log)
            run_client(proxy.port, secret, TAG_INT, 5, [b'z' * 12, b'w' * 20])
            assert len(dc.ws_log) == before, 'DC5 has no WS route but a WS connection was opened'
            assert dc.tcp_log and dc.tcp_log[-1]['dc_idx'] == 5, dc.tcp_log
        check('DC without WS route -> TCP fallback, relay init carries dc 5', tcp_fallback_no_ws_route)

        def wrong_secret():
            init, _, _ = make_client_init(os.urandom(16), TAG_ABR, 2)
            expect_closed(proxy.port, init)
        check('wrong secret -> connection closed', wrong_secret)

        def unsupported_dc():
            init, _, _ = make_client_init(secret, TAG_ABR, 9)
            expect_closed(proxy.port, init)
        check('unknown DC -> connection closed', unsupported_dc)

        def ws_redirect_falls_back():
            dc.mode = 'redirect'
            time.sleep(0.2)
            before = len(dc.tcp_log)
            # DC2 media was never used before, so its pool is empty and a new WS must be opened.
            run_client(proxy.port, secret, TAG_ABR, -2, [b'r' * 8], timeout=30)
            assert len(dc.tcp_log) == before + 1, 'expected TCP fallback after the 302'
            assert dc.tcp_log[-1]['dc_idx'] == -2, dc.tcp_log
            t0 = time.time()
            run_client(proxy.port, secret, TAG_ABR, -2, [b'r' * 8], timeout=30)
            assert time.time() - t0 < 2.0, 'second connection should skip WS during back-off'
            dc.mode = 'ok'
        check('WS answers 302 -> TCP fallback, then back-off skips WS', ws_redirect_falls_back)

        def no_server_errors():
            assert not dc.errors, '\n'.join(dc.errors)
        check('mock saw no protocol violations', no_server_errors)
    finally:
        proxy.stop()

    # ================= TLS: normal SNI + hostname verification =================
    cert, ctx = make_cert(['kws2.web.telegram.org', 'kws2-1.web.telegram.org'], tmp)
    dc_tls = MockDC(tls_ctx=ctx)
    proxy = Proxy(classes, secret, [
        '--ws-ip', '2:127.0.0.1', '--ws-port', str(dc_tls.ws_port), '--trust', cert,
        '--tcp-ip', '2:127.0.0.1', '--tcp-port', str(dc_tls.tcp_port), '--pool', '2'])
    try:
        def tls_normal():
            assert wait_for(lambda: dc_tls.ws_count >= 2), 'TLS pool did not pre-connect'
            run_client(proxy.port, secret, TAG_INT, 2, [b't' * 24, b'u' * 8])
            assert dc_tls.snis and all(n == 'kws2.web.telegram.org' for n in dc_tls.snis), dc_tls.snis
            assert not dc_tls.tcp_log, 'should not have fallen back to TCP'
            assert not dc_tls.errors, dc_tls.errors
        check('TLS: SNI = kws2.web.telegram.org, certificate verified, pooled', tls_normal)

        def tls_media_host():
            run_client(proxy.port, secret, TAG_INT, -2, [b'q' * 16])
            assert any(r['host'] == 'kws2-1.web.telegram.org' for r in dc_tls.ws_log), dc_tls.ws_log
        check('TLS: media DC uses kws2-1 host', tls_media_host)
    finally:
        proxy.stop()

    # ================= TLS: certificate does not match -> fronting attempt =================
    cert2, ctx2 = make_cert(['sprinthost.ru'], tmp)
    dc_front = MockDC(tls_ctx=ctx2)
    proxy = Proxy(classes, secret, [
        '--ws-ip', '2:127.0.0.1', '--ws-port', str(dc_front.ws_port), '--trust', cert2,
        '--tcp-ip', '2:127.0.0.1', '--tcp-port', str(dc_front.tcp_port), '--pool', '0'])
    try:
        def tls_fronting():
            run_client(proxy.port, secret, TAG_ABR, 2, [b'g' * 16])
            assert 'sprinthost.ru' in dc_front.snis, dc_front.snis
            used = [r for r in dc_front.ws_log if r.get('used')]
            assert used and used[-1]['host'] == 'kws2.web.telegram.org', dc_front.ws_log
            assert not dc_front.tcp_log, 'fronting should have worked, not TCP'
        check('TLS: normal attempt rejected by hostname check, fronting SNI works', tls_fronting)
    finally:
        proxy.stop()

    # ================= TLS: untrusted certificate must never be accepted =================
    other_cert, _ = make_cert(['unrelated.example'], tmp)
    dc_bad = MockDC(tls_ctx=make_cert(['kws2.web.telegram.org'], tmp)[1])
    proxy = Proxy(classes, secret, [
        '--ws-ip', '2:127.0.0.1', '--ws-port', str(dc_bad.ws_port), '--trust', other_cert,
        '--fronting-sni', '',
        '--tcp-ip', '2:127.0.0.1', '--tcp-port', str(dc_bad.tcp_port), '--pool', '0'])
    try:
        def tls_untrusted():
            run_client(proxy.port, secret, TAG_ABR, 2, [b'u' * 8])
            assert dc_bad.ws_count == 0, 'handshake must fail with an untrusted certificate'
            assert dc_bad.tcp_log, 'should have used the TCP fallback'
        check('TLS: untrusted certificate is refused, TCP fallback used', tls_untrusted)
    finally:
        proxy.stop()

    failed = [r for r in results if not r[1]]
    print('\n%d passed, %d failed' % (len(results) - len(failed), len(failed)))
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()

package dev.personal.tgws.core;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Minimal blocking RFC 6455 client: binary messages only, client frames are masked.
 * One thread may call send*(), another recv(); control replies from recv() are serialised
 * with sends through the write lock.
 */
public final class RawWebSocket implements Closeable {

    static final int OP_CONT = 0x0;
    static final int OP_TEXT = 0x1;
    static final int OP_BINARY = 0x2;
    static final int OP_CLOSE = 0x8;
    static final int OP_PING = 0x9;
    static final int OP_PONG = 0xA;

    static final int MAX_MESSAGE_LEN = 16 * 1024 * 1024;

    private static final SecureRandom RNG = new SecureRandom();

    /** The server answered the upgrade request with something other than 101. */
    public static final class HandshakeException extends IOException {
        private static final long serialVersionUID = 1L;

        public final int status;
        public final String location;

        HandshakeException(int status, String statusLine, String location) {
            super("HTTP " + status + ": " + statusLine);
            this.status = status;
            this.location = location;
        }

        public boolean isRedirect() {
            return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
        }
    }

    private final Socket socket;
    private final BufferedInputStream in;
    private final OutputStream out;
    private final ReentrantLock writeLock = new ReentrantLock();
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private ByteArrayOutputStream fragments; // touched only by the receiving thread

    private RawWebSocket(Socket socket, BufferedInputStream in, OutputStream out) {
        this.socket = socket;
        this.in = in;
        this.out = out;
    }

    /**
     * Opens a WebSocket.
     *
     * @param ip             literal IP to connect to (no DNS is involved)
     * @param host           value of the Host header (and the default TLS server name)
     * @param sni            TLS server name to send instead of host, or null
     * @param tls            false only in tests
     * @param verifyHostname check the certificate against the TLS server name
     * @param factory        socket factory for TLS (null = platform default)
     */
    public static RawWebSocket connect(String ip, int port, String host, String sni, boolean tls,
                                       boolean verifyHostname, String path, int timeoutMs,
                                       int bufferSize, SSLSocketFactory factory) throws IOException {
        Socket raw = new Socket();
        Socket sock = raw;
        try {
            raw.setTcpNoDelay(true);
            raw.setKeepAlive(true);
            if (bufferSize > 0) {
                raw.setReceiveBufferSize(bufferSize); // must precede connect() to affect the window
                raw.setSendBufferSize(bufferSize);
            }
            raw.connect(new InetSocketAddress(ip, port), timeoutMs);
            raw.setSoTimeout(timeoutMs);

            if (tls) {
                String serverName = (sni != null && !sni.isEmpty()) ? sni : host;
                SSLSocketFactory f = (factory != null) ? factory : (SSLSocketFactory) SSLSocketFactory.getDefault();
                SSLSocket ssl = (SSLSocket) f.createSocket(raw, serverName, port, true);
                sock = ssl;
                SSLParameters params = ssl.getSSLParameters();
                params.setServerNames(Collections.singletonList(new SNIHostName(serverName)));
                params.setEndpointIdentificationAlgorithm(verifyHostname ? "HTTPS" : null);
                ssl.setSSLParameters(params);
                ssl.startHandshake();
            }

            BufferedInputStream in = new BufferedInputStream(sock.getInputStream(), 16 * 1024);
            OutputStream out = sock.getOutputStream();

            String key = Base64.getEncoder().encodeToString(Util.random(16));
            String request = "GET " + path + " HTTP/1.1\r\n"
                + "Host: " + host + "\r\n"
                + "Upgrade: websocket\r\n"
                + "Connection: Upgrade\r\n"
                + "Sec-WebSocket-Key: " + key + "\r\n"
                + "Sec-WebSocket-Version: 13\r\n"
                + "Sec-WebSocket-Protocol: binary\r\n"
                + "\r\n";
            out.write(request.getBytes(StandardCharsets.ISO_8859_1));
            out.flush();

            String[] lines = readHeaderLines(in);
            if (lines.length == 0 || lines[0].isEmpty()) {
                throw new HandshakeException(0, "empty response", null);
            }
            String[] parts = lines[0].split(" ", 3);
            int status = 0;
            if (parts.length >= 2) {
                try {
                    status = Integer.parseInt(parts[1].trim());
                } catch (NumberFormatException ignored) {
                    status = 0;
                }
            }
            if (status != 101) {
                String location = null;
                for (int i = 1; i < lines.length; i++) {
                    int colon = lines[i].indexOf(':');
                    if (colon > 0 && lines[i].substring(0, colon).trim().equalsIgnoreCase("location")) {
                        location = lines[i].substring(colon + 1).trim();
                    }
                }
                throw new HandshakeException(status, lines[0], location);
            }

            sock.setSoTimeout(0);
            return new RawWebSocket(sock, in, out);
        } catch (IOException | RuntimeException e) {
            closeQuietly(sock);
            if (sock != raw) {
                closeQuietly(raw);
            }
            throw e;
        }
    }

    private static String[] readHeaderLines(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(256);
        int matched = 0; // progress through \r\n\r\n
        while (matched < 4) {
            int b = in.read();
            if (b < 0) {
                throw new EOFException("connection closed during WebSocket handshake");
            }
            buf.write(b);
            if (buf.size() > 16 * 1024) {
                throw new IOException("WebSocket handshake response too large");
            }
            boolean wantCr = (matched == 0 || matched == 2);
            if (wantCr && b == '\r') {
                matched++;
            } else if (!wantCr && b == '\n') {
                matched++;
            } else {
                matched = (b == '\r') ? 1 : 0;
            }
        }
        String text = new String(buf.toByteArray(), StandardCharsets.ISO_8859_1);
        return text.split("\r\n");
    }

    // ---- sending -----------------------------------------------------------------------------

    public void send(byte[] data) throws IOException {
        writeLock.lock();
        try {
            ensureOpen();
            writeFrame(OP_BINARY, data, 0, data.length);
            out.flush();
        } finally {
            writeLock.unlock();
        }
    }

    public void sendBatch(List<byte[]> parts) throws IOException {
        writeLock.lock();
        try {
            ensureOpen();
            for (byte[] p : parts) {
                writeFrame(OP_BINARY, p, 0, p.length);
            }
            out.flush();
        } finally {
            writeLock.unlock();
        }
    }

    private void ensureOpen() throws IOException {
        if (closed.get()) {
            throw new IOException("WebSocket closed");
        }
    }

    /** Control reply from the receiving thread; never throws. */
    private void sendControl(int opcode, byte[] payload) {
        writeLock.lock();
        try {
            writeFrame(opcode, payload, 0, payload.length);
            out.flush();
        } catch (IOException ignored) {
            // the receive loop will notice a dead connection by itself
        } finally {
            writeLock.unlock();
        }
    }

    private void writeFrame(int opcode, byte[] data, int off, int len) throws IOException {
        byte[] mask = new byte[4];
        RNG.nextBytes(mask);

        int headerLen = 2 + (len < 126 ? 0 : (len < 65536 ? 2 : 8)) + 4;
        byte[] frame = new byte[headerLen + len];
        int n = 0;
        frame[n++] = (byte) (0x80 | opcode);
        if (len < 126) {
            frame[n++] = (byte) (0x80 | len);
        } else if (len < 65536) {
            frame[n++] = (byte) (0x80 | 126);
            frame[n++] = (byte) (len >>> 8);
            frame[n++] = (byte) len;
        } else {
            frame[n++] = (byte) (0x80 | 127);
            for (int i = 7; i >= 0; i--) {
                frame[n++] = (byte) (((long) len >>> (8 * i)) & 0xFF);
            }
        }
        System.arraycopy(mask, 0, frame, n, 4);
        n += 4;
        for (int i = 0; i < len; i++) {
            frame[n + i] = (byte) (data[off + i] ^ mask[i & 3]);
        }
        out.write(frame);
    }

    // ---- receiving ---------------------------------------------------------------------------

    /** Next complete binary message, or null once the peer has closed the connection. */
    public byte[] recv() throws IOException {
        while (!closed.get()) {
            byte[] hdr = new byte[2];
            Util.readFully(in, hdr, 0, 2);
            boolean fin = (hdr[0] & 0x80) != 0;
            int opcode = hdr[0] & 0x0F;
            boolean masked = (hdr[1] & 0x80) != 0;
            long length = hdr[1] & 0x7F;
            if (length == 126) {
                byte[] ext = new byte[2];
                Util.readFully(in, ext, 0, 2);
                length = ((ext[0] & 0xFF) << 8) | (ext[1] & 0xFF);
            } else if (length == 127) {
                byte[] ext = new byte[8];
                Util.readFully(in, ext, 0, 8);
                length = 0;
                for (int i = 0; i < 8; i++) {
                    length = (length << 8) | (ext[i] & 0xFF);
                }
            }
            if (length < 0 || length > MAX_MESSAGE_LEN) {
                throw new IOException("WebSocket frame too large: " + length);
            }
            byte[] mask = null;
            if (masked) {
                mask = new byte[4];
                Util.readFully(in, mask, 0, 4);
            }
            byte[] payload = new byte[(int) length];
            Util.readFully(in, payload, 0, payload.length);
            if (masked) {
                for (int i = 0; i < payload.length; i++) {
                    payload[i] ^= mask[i & 3];
                }
            }

            switch (opcode) {
                case OP_CLOSE: {
                    boolean first = !closed.getAndSet(true);
                    if (first) {
                        byte[] echo = payload.length >= 2 ? new byte[]{payload[0], payload[1]} : new byte[0];
                        sendControl(OP_CLOSE, echo);
                        closeQuietly(socket);
                    }
                    return null;
                }
                case OP_PING:
                    sendControl(OP_PONG, payload);
                    continue;
                case OP_PONG:
                    continue;
                case OP_CONT:
                case OP_TEXT:
                case OP_BINARY:
                    if (fin && fragments == null) {
                        return payload;
                    }
                    if (fragments == null) {
                        fragments = new ByteArrayOutputStream();
                    }
                    fragments.write(payload, 0, payload.length);
                    if (fragments.size() > MAX_MESSAGE_LEN) {
                        throw new IOException("WebSocket message too large: " + fragments.size());
                    }
                    if (!fin) {
                        continue;
                    }
                    byte[] message = fragments.toByteArray();
                    fragments = null;
                    return message;
                default:
                    continue;
            }
        }
        return null;
    }

    // ---- housekeeping ------------------------------------------------------------------------

    public boolean isClosed() {
        return closed.get();
    }

    /**
     * For idle pooled connections: false if the peer hung up or sent anything at all
     * (an idle connection should be silent). Briefly polls the socket.
     */
    boolean isAlive() {
        if (closed.get()) {
            return false;
        }
        try {
            int old = socket.getSoTimeout();
            socket.setSoTimeout(1);
            try {
                in.read(); // a byte (stale) or EOF (closed) both mean "not usable"
                return false;
            } catch (SocketTimeoutException expected) {
                return true;
            } finally {
                socket.setSoTimeout(old);
            }
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    @Override
    public void close() {
        if (closed.getAndSet(true)) {
            closeQuietly(socket);
            return;
        }
        // Best-effort close frame; skip it if another thread is stuck writing.
        if (writeLock.tryLock()) {
            try {
                writeFrame(OP_CLOSE, new byte[0], 0, 0);
                out.flush();
            } catch (IOException | RuntimeException ignored) {
                // nothing to do
            } finally {
                writeLock.unlock();
            }
        }
        closeQuietly(socket);
    }

    private static void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (IOException ignored) {
            // nothing to do
        }
    }
}

package dev.personal.tgws.core;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

/**
 * Local MTProto proxy. Telegram connects here (127.0.0.1), we open a WebSocket to the right
 * Telegram datacenter and shuttle the re-encrypted stream; if that is not possible we connect to
 * the datacenter over plain TCP instead.
 */
public final class ProxyServer {

    private final ProxySettings cfg;
    private final Stats stats = new Stats();
    private final ExecutorService exec = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "tgws-io");
        t.setDaemon(true);
        return t;
    });
    private final WsPool pool;
    private final Set<Closeable> active = ConcurrentHashMap.newKeySet();
    private volatile ServerSocket server;
    private volatile boolean running;

    public ProxyServer(ProxySettings cfg) {
        this.cfg = cfg;
        this.pool = new WsPool(cfg, exec, stats);
    }

    public Stats stats() {
        return stats;
    }

    public void start() throws IOException {
        ServerSocket ss = new ServerSocket();
        try {
            ss.setReuseAddress(true);
            ss.bind(new InetSocketAddress(InetAddress.getByName(cfg.host), cfg.port), 128);
        } catch (IOException e) {
            closeQuietly(ss);
            throw e;
        }
        server = ss;
        running = true;
        Thread t = new Thread(this::acceptLoop, "tgws-accept");
        t.setDaemon(true);
        t.start();
        pool.warmup();
        ProxyLog.i("Listening on " + cfg.host + ":" + ss.getLocalPort());
    }

    public void stop() {
        running = false;
        ServerSocket ss = server;
        server = null;
        if (ss != null) {
            closeQuietly(ss);
        }
        pool.close();
        for (Closeable c : active) {
            closeQuietly(c);
        }
        active.clear();
        exec.shutdownNow();
    }

    // ---- accept loop -------------------------------------------------------------------------

    private void acceptLoop() {
        ServerSocket ss = server;
        while (running && ss != null) {
            try {
                Socket client = ss.accept();
                exec.execute(() -> handle(client));
            } catch (RejectedExecutionException e) {
                return;
            } catch (IOException e) {
                if (!running) {
                    return;
                }
                ProxyLog.w("accept failed: " + e);
                try {
                    Thread.sleep(200);
                } catch (InterruptedException ie) {
                    return;
                }
            }
        }
    }

    // ---- one client --------------------------------------------------------------------------

    private void handle(Socket client) {
        String label = "c" + client.getPort();
        stats.total.incrementAndGet();
        stats.active.incrementAndGet();
        active.add(client);
        try {
            client.setTcpNoDelay(true);
            client.setSoTimeout(10_000);
            InputStream cin = client.getInputStream();
            OutputStream cout = client.getOutputStream();

            byte[] init = new byte[MtProto.HANDSHAKE_LEN];
            Util.readFully(cin, init, 0, init.length);
            MtProto.Handshake hs = MtProto.tryHandshake(init, cfg.secret);
            if (hs == null) {
                stats.bad.incrementAndGet();
                ProxyLog.w("[" + label + "] bad handshake (wrong secret or transport)");
                return;
            }
            client.setSoTimeout(0);

            int dc = hs.dc;
            String dcTag = "DC" + dc + (hs.media ? "m" : "");
            if (!cfg.dcWsIps.containsKey(dc) && !cfg.dcTcpIps.containsKey(dc)) {
                ProxyLog.w("[" + label + "] unsupported " + dcTag);
                return;
            }

            byte[] relayInit = MtProto.generateRelayInit(hs.tag, hs.media ? -dc : dc);
            MtProto.CryptoCtx ctx = MtProto.buildCryptoCtx(hs.prekeyAndIv, cfg.secret, relayInit);

            WsPool.Lease lease = pool.get(dc, hs.media);
            RawWebSocket ws = null;
            if (lease != null) {
                ws = lease.ws;
                try {
                    ws.send(relayInit);
                } catch (IOException e) {
                    stats.wsErrors.incrementAndGet();
                    ProxyLog.d("[" + label + "] " + dcTag + " WS send failed: " + e);
                    ws.close();
                    ws = null;
                }
            }

            if (ws != null) {
                stats.ws.incrementAndGet();
                ProxyLog.d("[" + label + "] " + dcTag + " -> WS (" + (lease.pooled ? "pool" : "new") + ")");
                bridgeWs(client, cin, cout, ws, ctx, hs.proto, label, dcTag);
            } else {
                fallbackTcp(client, cin, cout, dc, relayInit, ctx, label, dcTag);
            }
        } catch (EOFException | SocketTimeoutException e) {
            ProxyLog.d("[" + label + "] client gone: " + e);
        } catch (IOException e) {
            ProxyLog.d("[" + label + "] I/O error: " + e);
        } catch (RuntimeException e) {
            ProxyLog.e("[" + label + "] unexpected: " + e);
        } finally {
            active.remove(client);
            closeQuietly(client);
            stats.active.decrementAndGet();
        }
    }

    private void bridgeWs(Socket client, InputStream cin, OutputStream cout, RawWebSocket ws,
                          MtProto.CryptoCtx ctx, int proto, String label, String dcTag) {
        MsgSplitter splitter = new MsgSplitter(proto);
        active.add(ws);

        // Telegram -> client
        exec.execute(() -> {
            try {
                while (true) {
                    byte[] message = ws.recv();
                    if (message == null) {
                        break;
                    }
                    stats.bytesDown.addAndGet(message.length);
                    byte[] plain = ctx.tgDec.update(message);
                    cout.write(ctx.cltEnc.update(plain));
                }
            } catch (IOException | RuntimeException e) {
                ProxyLog.d("[" + label + "] " + dcTag + " ws->client ended: " + e);
            } finally {
                ws.close();
                closeQuietly(client);
            }
        });

        // client -> Telegram
        try {
            byte[] buf = new byte[64 * 1024];
            while (true) {
                int n = cin.read(buf);
                if (n < 0) {
                    for (byte[] tail : splitter.flush()) {
                        ws.send(tail);
                    }
                    break;
                }
                stats.bytesUp.addAndGet(n);
                byte[] plain = ctx.cltDec.update(buf, 0, n);
                byte[] chunk = ctx.tgEnc.update(plain);
                List<byte[]> parts = splitter.split(chunk, plain);
                if (parts.size() == 1) {
                    ws.send(parts.get(0));
                } else if (parts.size() > 1) {
                    ws.sendBatch(parts);
                }
            }
        } catch (IOException | RuntimeException e) {
            ProxyLog.d("[" + label + "] " + dcTag + " client->ws ended: " + e);
        } finally {
            ws.close();
            closeQuietly(client);
            active.remove(ws);
        }
    }

    private void fallbackTcp(Socket client, InputStream cin, OutputStream cout, int dc, byte[] relayInit,
                             MtProto.CryptoCtx ctx, String label, String dcTag) {
        String dst = cfg.dcTcpIps.get(dc);
        if (dst == null) {
            ProxyLog.w("[" + label + "] " + dcTag + ": no WebSocket route and no TCP address");
            return;
        }
        Socket remote = new Socket();
        active.add(remote);
        try {
            remote.setTcpNoDelay(true);
            remote.connect(new InetSocketAddress(dst, cfg.tcpPort), 10_000);
            OutputStream rout = remote.getOutputStream();
            InputStream rin = remote.getInputStream();
            rout.write(relayInit);
            rout.flush();
            stats.tcp.incrementAndGet();
            ProxyLog.d("[" + label + "] " + dcTag + " -> TCP " + dst + ":" + cfg.tcpPort);

            // Telegram -> client
            exec.execute(() -> {
                try {
                    byte[] buf = new byte[64 * 1024];
                    while (true) {
                        int n = rin.read(buf);
                        if (n < 0) {
                            break;
                        }
                        stats.bytesDown.addAndGet(n);
                        byte[] plain = ctx.tgDec.update(buf, 0, n);
                        cout.write(ctx.cltEnc.update(plain));
                    }
                } catch (IOException | RuntimeException e) {
                    ProxyLog.d("[" + label + "] " + dcTag + " tcp->client ended: " + e);
                } finally {
                    closeQuietly(remote);
                    closeQuietly(client);
                }
            });

            // client -> Telegram
            byte[] buf = new byte[64 * 1024];
            while (true) {
                int n = cin.read(buf);
                if (n < 0) {
                    break;
                }
                stats.bytesUp.addAndGet(n);
                byte[] plain = ctx.cltDec.update(buf, 0, n);
                rout.write(ctx.tgEnc.update(plain));
            }
        } catch (IOException | RuntimeException e) {
            ProxyLog.w("[" + label + "] " + dcTag + " TCP fallback to " + dst + " failed: " + e);
        } finally {
            closeQuietly(remote);
            closeQuietly(client);
            active.remove(remote);
        }
    }

    private static void closeQuietly(Closeable c) {
        try {
            c.close();
        } catch (IOException | RuntimeException ignored) {
            // nothing to do
        }
    }
}

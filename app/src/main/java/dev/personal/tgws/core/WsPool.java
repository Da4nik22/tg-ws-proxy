package dev.personal.tgws.core;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;

import javax.net.ssl.SSLSocketFactory;

/**
 * Keeps a few ready WebSocket connections per DC and opens new ones on demand.
 * After a failure the DC is left alone for a growing delay, so clients fall back to TCP at once
 * instead of waiting for connect timeouts every time.
 */
final class WsPool {

    private static final long MAX_AGE_MS = 120_000L;
    private static final long BACKOFF_INITIAL_MS = 1_000L;
    private static final long BACKOFF_MAX_MS = 300_000L;

    /** A connection handed to a client. */
    static final class Lease {
        final RawWebSocket ws;
        final boolean pooled;

        Lease(RawWebSocket ws, boolean pooled) {
            this.ws = ws;
            this.pooled = pooled;
        }
    }

    private static final class Entry {
        final RawWebSocket ws;
        final long created = System.currentTimeMillis();

        Entry(RawWebSocket ws) {
            this.ws = ws;
        }
    }

    private static final class Health {
        int failures;
        long retryAt;
    }

    private final ProxySettings cfg;
    private final ExecutorService exec;
    private final Stats stats;
    private final Map<String, Deque<Entry>> idle = new ConcurrentHashMap<>();
    private final Map<String, Health> health = new ConcurrentHashMap<>();
    private final Set<String> refilling = ConcurrentHashMap.newKeySet();
    private volatile boolean closed;
    private volatile boolean frontingFirst;

    WsPool(ProxySettings cfg, ExecutorService exec, Stats stats) {
        this.cfg = cfg;
        this.exec = exec;
        this.stats = stats;
    }

    /** A WebSocket for the DC, or null when the caller should use the TCP fallback. */
    Lease get(int dc, boolean media) {
        String ip = cfg.dcWsIps.get(dc);
        if (ip == null || closed) {
            return null;
        }
        String key = key(dc, media);
        RawWebSocket ws = pollIdle(key);
        scheduleRefill(dc, media, ip);
        if (ws != null) {
            stats.poolHits.incrementAndGet();
            return new Lease(ws, true);
        }
        stats.poolMisses.incrementAndGet();
        if (inBackoff(key)) {
            return null;
        }
        ws = connectOne(dc, media, ip);
        return (ws == null) ? null : new Lease(ws, false);
    }

    void warmup() {
        for (Map.Entry<Integer, String> e : cfg.dcWsIps.entrySet()) {
            scheduleRefill(e.getKey(), false, e.getValue());
        }
    }

    void close() {
        closed = true;
        for (Deque<Entry> d : idle.values()) {
            synchronized (d) {
                for (Entry e : d) {
                    e.ws.close();
                }
                d.clear();
            }
        }
    }

    // ---- internals ---------------------------------------------------------------------------

    private static String key(int dc, boolean media) {
        return dc + (media ? "m" : "");
    }

    private RawWebSocket pollIdle(String key) {
        Deque<Entry> d = idle.get(key);
        if (d == null) {
            return null;
        }
        while (true) {
            Entry e;
            synchronized (d) {
                e = d.pollFirst();
            }
            if (e == null) {
                return null;
            }
            boolean stale = System.currentTimeMillis() - e.created >= MAX_AGE_MS || !e.ws.isAlive();
            if (stale) {
                e.ws.close();
                continue;
            }
            return e.ws;
        }
    }

    private void scheduleRefill(int dc, boolean media, String ip) {
        if (closed || cfg.poolSize <= 0) {
            return;
        }
        String key = key(dc, media);
        if (inBackoff(key) || !refilling.add(key)) {
            return;
        }
        try {
            exec.execute(() -> refill(key, dc, media, ip));
        } catch (RejectedExecutionException e) {
            refilling.remove(key);
        }
    }

    private void refill(String key, int dc, boolean media, String ip) {
        try {
            Deque<Entry> d = idle.computeIfAbsent(key, k -> new ArrayDeque<>());
            purgeStale(d);
            while (!closed) {
                int have;
                synchronized (d) {
                    have = d.size();
                }
                if (have >= cfg.poolSize) {
                    break;
                }
                RawWebSocket ws = connectOne(dc, media, ip);
                if (ws == null) {
                    break;
                }
                if (closed) {
                    ws.close();
                    break;
                }
                synchronized (d) {
                    d.addLast(new Entry(ws));
                }
            }
        } catch (RuntimeException e) {
            ProxyLog.d("WS pool refill " + key + " failed: " + e);
        } finally {
            refilling.remove(key);
        }
    }

    private void purgeStale(Deque<Entry> d) {
        long now = System.currentTimeMillis();
        synchronized (d) {
            Iterator<Entry> it = d.iterator();
            while (it.hasNext()) {
                Entry e = it.next();
                if (now - e.created >= MAX_AGE_MS) {
                    it.remove();
                    e.ws.close();
                }
            }
        }
    }

    private RawWebSocket connectOne(int dc, boolean media, String ip) {
        String key = key(dc, media);
        boolean canFront = cfg.frontingSni != null && !cfg.frontingSni.isEmpty();
        boolean[] order = (frontingFirst && canFront) ? new boolean[]{true, false} : new boolean[]{false, true};
        SSLSocketFactory factory = cfg.sslFactory;

        for (String domain : DcInfo.wsDomains(dc, media)) {
            for (boolean fronted : order) {
                if (fronted && !canFront) {
                    continue;
                }
                try {
                    RawWebSocket ws = RawWebSocket.connect(
                        ip, cfg.wsPort, domain,
                        fronted ? cfg.frontingSni : null,
                        cfg.wsTls, !fronted, DcInfo.WS_PATH,
                        fronted ? 7000 : 8000, cfg.bufferSize, factory);
                    frontingFirst = fronted;
                    if (fronted) {
                        stats.fronting.incrementAndGet();
                    }
                    health.remove(key);
                    ProxyLog.d("WS connected " + domain + " via " + ip + (fronted ? " (fronting)" : ""));
                    return ws;
                } catch (IOException | RuntimeException e) {
                    stats.wsErrors.incrementAndGet();
                    ProxyLog.d("WS connect " + domain + " via " + ip + (fronted ? " (fronting)" : "") + ": " + e);
                }
            }
        }
        markFailure(key);
        return null;
    }

    private boolean inBackoff(String key) {
        Health h = health.get(key);
        return h != null && System.currentTimeMillis() < h.retryAt;
    }

    private void markFailure(String key) {
        Health h = health.computeIfAbsent(key, k -> new Health());
        synchronized (h) {
            h.failures++;
            long delay = Math.min(BACKOFF_INITIAL_MS << Math.min(h.failures - 1, 9), BACKOFF_MAX_MS);
            h.retryAt = System.currentTimeMillis() + delay;
        }
    }
}

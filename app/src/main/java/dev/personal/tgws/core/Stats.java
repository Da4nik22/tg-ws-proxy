package dev.personal.tgws.core;

import java.util.concurrent.atomic.AtomicLong;

public final class Stats {

    public final AtomicLong total = new AtomicLong();
    public final AtomicLong active = new AtomicLong();
    public final AtomicLong ws = new AtomicLong();
    public final AtomicLong tcp = new AtomicLong();
    public final AtomicLong bad = new AtomicLong();
    public final AtomicLong wsErrors = new AtomicLong();
    public final AtomicLong fronting = new AtomicLong();
    public final AtomicLong poolHits = new AtomicLong();
    public final AtomicLong poolMisses = new AtomicLong();
    public final AtomicLong bytesUp = new AtomicLong();
    public final AtomicLong bytesDown = new AtomicLong();

    public String summary() {
        return "connections: " + total.get() + " total, " + active.get() + " active\n"
            + "routes: WS " + ws.get() + " (pool " + poolHits.get() + "/" + (poolHits.get() + poolMisses.get())
            + ", fronting " + fronting.get() + "), TCP " + tcp.get() + "\n"
            + "errors: WS " + wsErrors.get() + ", bad handshake " + bad.get() + "\n"
            + "traffic: up " + human(bytesUp.get()) + ", down " + human(bytesDown.get());
    }

    static String human(long n) {
        double v = n;
        String[] units = {"B", "KB", "MB", "GB"};
        int i = 0;
        while (v >= 1024 && i < units.length - 1) {
            v /= 1024;
            i++;
        }
        return String.format(java.util.Locale.US, "%.1f %s", v, units[i]);
    }
}

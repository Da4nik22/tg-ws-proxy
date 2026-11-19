package dev.personal.tgws;

import android.util.Log;

import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.Date;
import java.util.Locale;

import dev.personal.tgws.core.ProxyLog;

/** Last few hundred log lines, newest first, for the on-screen log. */
final class LogBuffer {

    private static final int MAX_LINES = 300;
    private static final ArrayDeque<String> LINES = new ArrayDeque<>();
    private static final SimpleDateFormat TIME = new SimpleDateFormat("HH:mm:ss", Locale.US);
    private static boolean installed;

    private LogBuffer() {
    }

    /** Routes the core's log into this buffer and logcat. Safe to call repeatedly. */
    static synchronized void install() {
        if (installed) {
            return;
        }
        installed = true;
        ProxyLog.setSink((level, message) -> {
            add(level + " " + message);
            Log.println("E".equals(level) ? Log.ERROR : "W".equals(level) ? Log.WARN : Log.INFO, "tgws", message);
        });
    }

    static synchronized void add(String line) {
        LINES.addFirst(TIME.format(new Date()) + " " + line);
        while (LINES.size() > MAX_LINES) {
            LINES.removeLast();
        }
    }

    static synchronized String snapshot() {
        StringBuilder sb = new StringBuilder();
        for (String l : LINES) {
            sb.append(l).append('\n');
        }
        return sb.toString();
    }
}

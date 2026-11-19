package dev.personal.tgws.core;

/** Tiny logging facade so the core stays free of Android classes. */
public final class ProxyLog {

    public interface Sink {
        void line(String level, String message);
    }

    private static volatile Sink sink = (level, message) -> System.out.println(level + " " + message);

    /** Debug lines are dropped unless this is true. */
    public static volatile boolean verbose = false;

    private ProxyLog() {
    }

    public static void setSink(Sink s) {
        sink = (s != null) ? s : (level, message) -> { };
    }

    public static void i(String message) {
        sink.line("I", message);
    }

    public static void w(String message) {
        sink.line("W", message);
    }

    public static void e(String message) {
        sink.line("E", message);
    }

    public static void d(String message) {
        if (verbose) {
            sink.line("D", message);
        }
    }
}

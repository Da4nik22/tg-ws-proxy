package dev.personal.tgws;

import dev.personal.tgws.core.ProxyServer;

/** What the service is doing right now; read by the screen and the notification. */
final class ProxyRuntime {

    enum Status { STOPPED, STARTING, RUNNING, FAILED }

    private static volatile Status status = Status.STOPPED;
    private static volatile String detail = "";
    private static volatile ProxyServer server;

    private ProxyRuntime() {
    }

    static Status status() {
        return status;
    }

    static String detail() {
        return detail;
    }

    static ProxyServer server() {
        return server;
    }

    static void set(Status s, String d) {
        status = s;
        detail = d;
    }

    static void setServer(ProxyServer s) {
        server = s;
    }
}

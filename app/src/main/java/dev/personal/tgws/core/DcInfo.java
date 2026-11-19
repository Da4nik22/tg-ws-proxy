package dev.personal.tgws.core;

import java.util.LinkedHashMap;
import java.util.Map;

/** Telegram datacenter constants (mirrors upstream tg-ws-proxy). */
public final class DcInfo {

    public static final String WS_PATH = "/apiws";

    /** Where plain TCP goes when the WebSocket route is not available. */
    public static Map<Integer, String> defaultTcpIps() {
        Map<Integer, String> m = new LinkedHashMap<>();
        m.put(1, "149.154.175.50");
        m.put(2, "149.154.167.51");
        m.put(3, "149.154.175.100");
        m.put(4, "149.154.167.91");
        m.put(5, "149.154.171.5");
        m.put(203, "91.105.192.100");
        return m;
    }

    /** DCs that are reachable over WebSocket, and the IP to connect to for them. */
    public static Map<Integer, String> defaultWsIps() {
        Map<Integer, String> m = new LinkedHashMap<>();
        m.put(2, "149.154.167.220");
        m.put(4, "149.154.167.220");
        return m;
    }

    /** Hostnames to try for a DC, in order. They go into SNI and the Host header. */
    static String[] wsDomains(int dc, boolean media) {
        int d = (dc == 203) ? 2 : dc;
        if (!media) {
            return new String[]{"kws" + d + ".web.telegram.org"};
        }
        return new String[]{"kws" + d + "-1.web.telegram.org", "kws" + d + ".web.telegram.org"};
    }

    private DcInfo() {
    }
}

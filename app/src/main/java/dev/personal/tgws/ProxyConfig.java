package dev.personal.tgws;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

import dev.personal.tgws.core.DcInfo;
import dev.personal.tgws.core.ProxySettings;
import dev.personal.tgws.core.Util;

/** Settings stored in SharedPreferences, plus the Telegram link built from them. */
final class ProxyConfig {

    static final String HOST = "127.0.0.1";
    static final int DEFAULT_PORT = 1443;
    static final int DEFAULT_POOL = 4;
    static final String DEFAULT_DC_IPS = "2:149.154.167.220, 4:149.154.167.220";

    private static final Pattern IPV4 = Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");

    private final SharedPreferences sp;

    ProxyConfig(Context context) {
        sp = context.getSharedPreferences("tgws", Context.MODE_PRIVATE);
    }

    int port() {
        return sp.getInt("port", DEFAULT_PORT);
    }

    String dcIps() {
        return sp.getString("dcIps", DEFAULT_DC_IPS);
    }

    int pool() {
        return sp.getInt("pool", DEFAULT_POOL);
    }

    boolean verbose() {
        return sp.getBoolean("verbose", false);
    }

    /** Start the proxy when the phone boots and after the app is updated. */
    boolean autostartBoot() {
        return sp.getBoolean("autostartBoot", false);
    }

    void setAutostartBoot(boolean enabled) {
        sp.edit().putBoolean("autostartBoot", enabled).apply();
    }

    /** Start the proxy whenever the app is opened and the proxy is not running. */
    boolean autostartOpen() {
        return sp.getBoolean("autostartOpen", false);
    }

    void setAutostartOpen(boolean enabled) {
        sp.edit().putBoolean("autostartOpen", enabled).apply();
    }

    /** 32 hex characters; generated once and then kept, so the Telegram link stays the same. */
    String secretHex() {
        String s = sp.getString("secret", null);
        if (s == null || !s.matches("[0-9a-f]{32}")) {
            s = Util.hex(Util.random(16));
            sp.edit().putString("secret", s).apply();
        }
        return s;
    }

    String link() {
        return "tg://proxy?server=" + HOST + "&port=" + port() + "&secret=dd" + secretHex();
    }

    void save(int port, String dcIps, int pool, boolean verbose) {
        sp.edit()
            .putInt("port", port)
            .putString("dcIps", dcIps)
            .putInt("pool", pool)
            .putBoolean("verbose", verbose)
            .apply();
    }

    /** Throws IllegalArgumentException with a readable message when a stored value is invalid. */
    ProxySettings toSettings() {
        ProxySettings s = new ProxySettings();
        s.host = HOST;
        s.port = port();
        s.secret = Util.fromHex(secretHex());
        s.dcWsIps = parseDcIps(dcIps());
        s.dcTcpIps = DcInfo.defaultTcpIps();
        s.poolSize = pool();
        return s;
    }

    /** "2:149.154.167.220, 4:149.154.167.220" -> {2=..., 4=...}. Empty input = no WebSocket DCs. */
    static Map<Integer, String> parseDcIps(String text) {
        Map<Integer, String> result = new LinkedHashMap<>();
        if (text == null) {
            return result;
        }
        for (String item : text.split("[,;\\s]+")) {
            if (item.isEmpty()) {
                continue;
            }
            String[] p = item.split(":");
            if (p.length != 2) {
                throw new IllegalArgumentException("expected DC:IP, got \"" + item + "\"");
            }
            int dc;
            try {
                dc = Integer.parseInt(p[0]);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("bad DC number in \"" + item + "\"");
            }
            if (dc < 1 || dc > 5) {
                throw new IllegalArgumentException("DC must be 1..5, got " + dc);
            }
            java.util.regex.Matcher m = IPV4.matcher(p[1]);
            if (!m.matches()) {
                throw new IllegalArgumentException("bad IPv4 address in \"" + item + "\"");
            }
            for (int i = 1; i <= 4; i++) {
                if (Integer.parseInt(m.group(i)) > 255) {
                    throw new IllegalArgumentException("bad IPv4 address in \"" + item + "\"");
                }
            }
            result.put(dc, p[1]);
        }
        return result;
    }
}

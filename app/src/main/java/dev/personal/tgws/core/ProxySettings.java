package dev.personal.tgws.core;

import java.util.Map;

import javax.net.ssl.SSLSocketFactory;

/** Plain settings holder; fill the fields, then hand it to {@link ProxyServer}. */
public final class ProxySettings {

    /** Address the local proxy listens on. Keep it loopback. */
    public String host = "127.0.0.1";
    public int port = 1443;

    /** 16-byte proxy secret; the Telegram link carries it as "dd" + hex. */
    public byte[] secret;

    /** DC -> IP for the WebSocket route. A DC missing here goes straight to TCP. */
    public Map<Integer, String> dcWsIps = DcInfo.defaultWsIps();

    /** DC -> IP for the direct TCP fallback. */
    public Map<Integer, String> dcTcpIps = DcInfo.defaultTcpIps();

    /** Idle WebSocket connections kept ready per DC (0 disables the pool). */
    public int poolSize = 4;

    public int bufferSize = 256 * 1024;

    /** Second WebSocket attempt uses this TLS server name without hostname checks. Empty = off. */
    public String frontingSni = "sprinthost.ru";

    // Knobs that only tests change.
    public int wsPort = 443;
    public boolean wsTls = true;
    public int tcpPort = 443;
    public SSLSocketFactory sslFactory = null;
}

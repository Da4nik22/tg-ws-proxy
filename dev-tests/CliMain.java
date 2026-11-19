package dev.personal.tgws.core;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * Desktop launcher for the proxy core, used by dev-tests/test_proxy.py. Not part of the APK.
 *
 *   --port N --secret HEX32 --ws-ip DC:IP --tcp-ip DC:IP --ws-port N --tcp-port N
 *   --pool N --no-tls --trust cert.pem --fronting-sni NAME -v
 */
public final class CliMain {

    public static void main(String[] a) throws Exception {
        ProxySettings s = new ProxySettings();
        s.dcWsIps = new LinkedHashMap<>();
        s.dcTcpIps = new LinkedHashMap<>();
        for (int i = 0; i < a.length; i++) {
            switch (a[i]) {
                case "--port": s.port = Integer.parseInt(a[++i]); break;
                case "--secret": s.secret = Util.fromHex(a[++i]); break;
                case "--ws-ip": put(s.dcWsIps, a[++i]); break;
                case "--tcp-ip": put(s.dcTcpIps, a[++i]); break;
                case "--ws-port": s.wsPort = Integer.parseInt(a[++i]); break;
                case "--tcp-port": s.tcpPort = Integer.parseInt(a[++i]); break;
                case "--pool": s.poolSize = Integer.parseInt(a[++i]); break;
                case "--no-tls": s.wsTls = false; break;
                case "--fronting-sni": s.frontingSni = a[++i]; break;
                case "--trust": s.sslFactory = trusting(a[++i]); break;
                case "-v": ProxyLog.verbose = true; break;
                default: throw new IllegalArgumentException("unknown arg " + a[i]);
            }
        }
        ProxyServer srv = new ProxyServer(s);
        srv.start();
        System.out.println("LISTENING");
        System.out.flush();
        Thread.currentThread().join();
    }

    private static void put(java.util.Map<Integer, String> m, String spec) {
        String[] p = spec.split(":", 2);
        m.put(Integer.parseInt(p[0]), p[1]);
    }

    private static javax.net.ssl.SSLSocketFactory trusting(String pem) throws Exception {
        X509Certificate cert;
        try (FileInputStream in = new FileInputStream(pem)) {
            cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null);
        ks.setCertificateEntry("test", cert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);
        return ctx.getSocketFactory();
    }

    private CliMain() {
    }
}

package dev.personal.tgws.core;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class Util {

    private static final SecureRandom RNG = new SecureRandom();
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Util() {
    }

    public static byte[] random(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    public static byte[] sha256(byte[] a, byte[] b) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(a);
            md.update(b);
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] reversed(byte[] a) {
        byte[] r = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            r[i] = a[a.length - 1 - i];
        }
        return r;
    }

    public static String hex(byte[] b) {
        char[] out = new char[b.length * 2];
        for (int i = 0; i < b.length; i++) {
            out[2 * i] = HEX[(b[i] >> 4) & 0xF];
            out[2 * i + 1] = HEX[b[i] & 0xF];
        }
        return new String(out);
    }

    public static byte[] fromHex(String s) {
        if (s.length() % 2 != 0) {
            throw new IllegalArgumentException("odd hex length");
        }
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(s.charAt(2 * i), 16);
            int lo = Character.digit(s.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("not hex: " + s);
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    /** Reads exactly len bytes or throws EOFException. */
    public static void readFully(InputStream in, byte[] buf, int off, int len) throws IOException {
        while (len > 0) {
            int n = in.read(buf, off, len);
            if (n < 0) {
                throw new EOFException();
            }
            off += n;
            len -= n;
        }
    }

    static boolean startsWith(byte[] a, byte[] prefix) {
        if (a.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (a[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }
}

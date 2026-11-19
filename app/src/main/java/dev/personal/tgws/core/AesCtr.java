package dev.personal.tgws.core;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** AES-256-CTR keystream with a big-endian 128-bit counter (what MTProto obfuscation uses). */
final class AesCtr {

    private final Cipher cipher;

    AesCtr(byte[] key, byte[] iv) {
        try {
            cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    byte[] update(byte[] data) {
        return update(data, 0, data.length);
    }

    byte[] update(byte[] data, int off, int len) {
        if (len == 0) {
            return new byte[0];
        }
        byte[] out = cipher.update(data, off, len);
        if (out == null || out.length != len) {
            throw new IllegalStateException("CTR returned an unexpected length");
        }
        return out;
    }
}

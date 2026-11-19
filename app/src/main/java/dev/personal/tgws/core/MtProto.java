package dev.personal.tgws.core;

import java.util.Arrays;

/**
 * MTProto proxy handshake ("obfuscated2" with a proxy secret).
 *
 * The Telegram app talks to us as to a normal MTProto proxy: its 64-byte init is encrypted with
 * SHA256(prekey + secret). Towards Telegram we generate a fresh standard init (no secret) and
 * re-encrypt the stream in both directions.
 */
final class MtProto {

    static final int HANDSHAKE_LEN = 64;
    static final int SKIP_LEN = 8;
    static final int PREKEY_LEN = 32;
    static final int KEY_LEN = 32;
    static final int IV_LEN = 16;
    static final int PROTO_TAG_POS = 56;
    static final int DC_IDX_POS = 60;

    static final byte[] TAG_ABRIDGED = {(byte) 0xEF, (byte) 0xEF, (byte) 0xEF, (byte) 0xEF};
    static final byte[] TAG_INTERMEDIATE = {(byte) 0xEE, (byte) 0xEE, (byte) 0xEE, (byte) 0xEE};
    static final byte[] TAG_SECURE = {(byte) 0xDD, (byte) 0xDD, (byte) 0xDD, (byte) 0xDD};

    static final int PROTO_ABRIDGED = 0xEFEFEFEF;
    static final int PROTO_INTERMEDIATE = 0xEEEEEEEE;
    static final int PROTO_PADDED_INTERMEDIATE = 0xDDDDDDDD;

    private static final byte[] ZERO_64 = new byte[HANDSHAKE_LEN];

    /** First four bytes an init must not start with (they look like HTTP / TLS / other transports). */
    private static final byte[][] RESERVED_STARTS = {
        {0x48, 0x45, 0x41, 0x44},                       // HEAD
        {0x50, 0x4F, 0x53, 0x54},                       // POST
        {0x47, 0x45, 0x54, 0x20},                       // GET
        TAG_INTERMEDIATE,
        TAG_SECURE,
        {0x16, 0x03, 0x01, 0x02},                       // TLS
        {0x4F, 0x50, 0x54, 0x49},                       // OPTI
    };

    private MtProto() {
    }

    static final class Handshake {
        final int dc;
        final boolean media;
        final byte[] tag;
        final int proto;
        /** Bytes 8..56 of the client's init: its prekey and IV. */
        final byte[] prekeyAndIv;

        Handshake(int dc, boolean media, byte[] tag, int proto, byte[] prekeyAndIv) {
            this.dc = dc;
            this.media = media;
            this.tag = tag;
            this.proto = proto;
            this.prekeyAndIv = prekeyAndIv;
        }
    }

    static final class CryptoCtx {
        /** Decrypts data coming from the client. */
        final AesCtr cltDec;
        /** Encrypts data going to the client. */
        final AesCtr cltEnc;
        /** Encrypts data going to Telegram. */
        final AesCtr tgEnc;
        /** Decrypts data coming from Telegram. */
        final AesCtr tgDec;

        CryptoCtx(AesCtr cltDec, AesCtr cltEnc, AesCtr tgEnc, AesCtr tgDec) {
            this.cltDec = cltDec;
            this.cltEnc = cltEnc;
            this.tgEnc = tgEnc;
            this.tgDec = tgDec;
        }
    }

    /** Null when the secret is wrong or the transport is not abridged / intermediate / padded. */
    static Handshake tryHandshake(byte[] init, byte[] secret) {
        if (init.length < HANDSHAKE_LEN) {
            return null;
        }
        byte[] prekeyAndIv = Arrays.copyOfRange(init, SKIP_LEN, SKIP_LEN + PREKEY_LEN + IV_LEN);
        byte[] prekey = Arrays.copyOfRange(prekeyAndIv, 0, PREKEY_LEN);
        byte[] iv = Arrays.copyOfRange(prekeyAndIv, PREKEY_LEN, PREKEY_LEN + IV_LEN);
        byte[] key = Util.sha256(prekey, secret);
        byte[] dec = new AesCtr(key, iv).update(init, 0, HANDSHAKE_LEN);

        byte[] tag = Arrays.copyOfRange(dec, PROTO_TAG_POS, PROTO_TAG_POS + 4);
        int proto;
        if (Arrays.equals(tag, TAG_ABRIDGED)) {
            proto = PROTO_ABRIDGED;
        } else if (Arrays.equals(tag, TAG_INTERMEDIATE)) {
            proto = PROTO_INTERMEDIATE;
        } else if (Arrays.equals(tag, TAG_SECURE)) {
            proto = PROTO_PADDED_INTERMEDIATE;
        } else {
            return null;
        }

        int dcIdx = (short) ((dec[DC_IDX_POS] & 0xFF) | ((dec[DC_IDX_POS + 1] & 0xFF) << 8));
        return new Handshake(Math.abs(dcIdx), dcIdx < 0, tag, proto, prekeyAndIv);
    }

    /** A fresh standard obfuscated2 init for the connection to Telegram. */
    static byte[] generateRelayInit(byte[] protoTag, int dcIdx) {
        byte[] rnd;
        while (true) {
            rnd = Util.random(HANDSHAKE_LEN);
            if ((rnd[0] & 0xFF) == 0xEF) {
                continue;
            }
            boolean reserved = false;
            for (byte[] r : RESERVED_STARTS) {
                if (Util.startsWith(rnd, r)) {
                    reserved = true;
                    break;
                }
            }
            if (reserved) {
                continue;
            }
            if (rnd[4] == 0 && rnd[5] == 0 && rnd[6] == 0 && rnd[7] == 0) {
                continue;
            }
            break;
        }

        byte[] encKey = Arrays.copyOfRange(rnd, SKIP_LEN, SKIP_LEN + PREKEY_LEN);
        byte[] encIv = Arrays.copyOfRange(rnd, SKIP_LEN + PREKEY_LEN, SKIP_LEN + PREKEY_LEN + IV_LEN);
        byte[] encryptedFull = new AesCtr(encKey, encIv).update(rnd);

        byte[] tailPlain = new byte[8];
        System.arraycopy(protoTag, 0, tailPlain, 0, 4);
        tailPlain[4] = (byte) (dcIdx & 0xFF);
        tailPlain[5] = (byte) ((dcIdx >> 8) & 0xFF);
        byte[] pad = Util.random(2);
        tailPlain[6] = pad[0];
        tailPlain[7] = pad[1];

        byte[] result = rnd.clone();
        for (int i = 0; i < 8; i++) {
            int keystream = (encryptedFull[PROTO_TAG_POS + i] ^ rnd[PROTO_TAG_POS + i]) & 0xFF;
            result[PROTO_TAG_POS + i] = (byte) ((tailPlain[i] & 0xFF) ^ keystream);
        }
        return result;
    }

    /** Client-side keys come from the secret, Telegram-side keys from relayInit. */
    static CryptoCtx buildCryptoCtx(byte[] clientPrekeyAndIv, byte[] secret, byte[] relayInit) {
        byte[] cltDecKey = Util.sha256(Arrays.copyOfRange(clientPrekeyAndIv, 0, PREKEY_LEN), secret);
        byte[] cltDecIv = Arrays.copyOfRange(clientPrekeyAndIv, PREKEY_LEN, PREKEY_LEN + IV_LEN);

        byte[] cltEncPrekeyIv = Util.reversed(clientPrekeyAndIv);
        byte[] cltEncKey = Util.sha256(Arrays.copyOfRange(cltEncPrekeyIv, 0, PREKEY_LEN), secret);
        byte[] cltEncIv = Arrays.copyOfRange(cltEncPrekeyIv, PREKEY_LEN, PREKEY_LEN + IV_LEN);

        AesCtr cltDec = new AesCtr(cltDecKey, cltDecIv);
        AesCtr cltEnc = new AesCtr(cltEncKey, cltEncIv);
        cltDec.update(ZERO_64); // skip the client's init

        byte[] relayEncKey = Arrays.copyOfRange(relayInit, SKIP_LEN, SKIP_LEN + PREKEY_LEN);
        byte[] relayEncIv = Arrays.copyOfRange(relayInit, SKIP_LEN + PREKEY_LEN, SKIP_LEN + PREKEY_LEN + IV_LEN);
        byte[] relayDecPrekeyIv = Util.reversed(
            Arrays.copyOfRange(relayInit, SKIP_LEN, SKIP_LEN + PREKEY_LEN + IV_LEN));
        byte[] relayDecKey = Arrays.copyOfRange(relayDecPrekeyIv, 0, KEY_LEN);
        byte[] relayDecIv = Arrays.copyOfRange(relayDecPrekeyIv, KEY_LEN, KEY_LEN + IV_LEN);

        AesCtr tgEnc = new AesCtr(relayEncKey, relayEncIv);
        AesCtr tgDec = new AesCtr(relayDecKey, relayDecIv);
        tgEnc.update(ZERO_64); // skip our own init

        return new CryptoCtx(cltDec, cltEnc, tgEnc, tgDec);
    }
}

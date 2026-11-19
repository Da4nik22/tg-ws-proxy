package dev.personal.tgws.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Splits the client's TCP byte stream into individual MTProto transport packets, so that every
 * packet travels as its own WebSocket message. The packet boundaries are read from the
 * decrypted stream; the ciphertext (re-encrypted for Telegram) is what gets cut.
 */
final class MsgSplitter {

    /** Anything bigger than this is not a sane packet: stop splitting and pass data through. */
    private static final long MAX_PACKET = 32L * 1024 * 1024;

    private final int proto;
    private byte[] cipher = new byte[8192];
    private byte[] plain = new byte[8192];
    private int len = 0;
    private boolean disabled = false;

    MsgSplitter(int proto) {
        this.proto = proto;
    }

    List<byte[]> split(byte[] cipherChunk, byte[] plainChunk) {
        if (cipherChunk.length == 0) {
            return Collections.emptyList();
        }
        if (disabled) {
            return Collections.singletonList(cipherChunk);
        }
        ensureCapacity(len + cipherChunk.length);
        System.arraycopy(cipherChunk, 0, cipher, len, cipherChunk.length);
        System.arraycopy(plainChunk, 0, plain, len, plainChunk.length);
        len += cipherChunk.length;

        List<byte[]> parts = new ArrayList<>(2);
        int offset = 0;
        while (offset < len) {
            int packetLen = nextPacketLen(offset, len - offset);
            if (packetLen < 0) {
                break; // need more data
            }
            if (packetLen == 0) {
                // Unknown framing: forward the rest as is and stop splitting.
                parts.add(Arrays.copyOfRange(cipher, offset, len));
                offset = len;
                disabled = true;
                break;
            }
            parts.add(Arrays.copyOfRange(cipher, offset, offset + packetLen));
            offset += packetLen;
        }
        if (offset > 0) {
            System.arraycopy(cipher, offset, cipher, 0, len - offset);
            System.arraycopy(plain, offset, plain, 0, len - offset);
            len -= offset;
        }
        return parts;
    }

    /** Whatever is still buffered (an incomplete packet when the client hangs up). */
    List<byte[]> flush() {
        if (len == 0) {
            return Collections.emptyList();
        }
        byte[] tail = Arrays.copyOfRange(cipher, 0, len);
        len = 0;
        return Collections.singletonList(tail);
    }

    private void ensureCapacity(int needed) {
        if (needed <= cipher.length) {
            return;
        }
        int cap = Math.max(needed, cipher.length * 2);
        cipher = Arrays.copyOf(cipher, cap);
        plain = Arrays.copyOf(plain, cap);
    }

    /** -1: need more data, 0: unknown framing, otherwise the length of the next packet. */
    private int nextPacketLen(int offset, int avail) {
        if (avail <= 0) {
            return -1;
        }
        if (proto == MtProto.PROTO_ABRIDGED) {
            return abridgedLen(offset, avail);
        }
        if (proto == MtProto.PROTO_INTERMEDIATE || proto == MtProto.PROTO_PADDED_INTERMEDIATE) {
            return intermediateLen(offset, avail);
        }
        return 0;
    }

    private int abridgedLen(int offset, int avail) {
        int first = plain[offset] & 0xFF;
        long payload;
        int header;
        if (first == 0x7F || first == 0xFF) {
            if (avail < 4) {
                return -1;
            }
            long words = (plain[offset + 1] & 0xFFL)
                | ((plain[offset + 2] & 0xFFL) << 8)
                | ((plain[offset + 3] & 0xFFL) << 16);
            payload = words * 4;
            header = 4;
        } else {
            payload = (first & 0x7F) * 4L;
            header = 1;
        }
        if (payload <= 0) {
            return 0;
        }
        long packet = header + payload;
        if (packet > MAX_PACKET) {
            return 0;
        }
        if (avail < packet) {
            return -1;
        }
        return (int) packet;
    }

    private int intermediateLen(int offset, int avail) {
        if (avail < 4) {
            return -1;
        }
        long payload = ((plain[offset] & 0xFFL)
            | ((plain[offset + 1] & 0xFFL) << 8)
            | ((plain[offset + 2] & 0xFFL) << 16)
            | ((plain[offset + 3] & 0xFFL) << 24)) & 0x7FFFFFFFL;
        if (payload <= 0) {
            return 0;
        }
        long packet = 4 + payload;
        if (packet > MAX_PACKET) {
            return 0;
        }
        if (avail < packet) {
            return -1;
        }
        return (int) packet;
    }
}

package org.nexxus.protocol;

import java.security.SecureRandom;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/** XChaCha20-Poly1305. Packed form matches linux-node: nonce(24) || ciphertext || tag(16). */
public final class Aead {
    public static final int NONCE = 24;
    private static final SecureRandom RNG = new SecureRandom();

    private Aead() {}

    public static byte[] seal(byte[] key, byte[] plain) {
        byte[] nonce = new byte[NONCE];
        RNG.nextBytes(nonce);
        byte[] ct = sealWithNonce(key, nonce, plain);
        byte[] out = new byte[NONCE + ct.length];
        System.arraycopy(nonce, 0, out, 0, NONCE);
        System.arraycopy(ct, 0, out, NONCE, ct.length);
        return out;
    }

    public static byte[] sealWithNonce(byte[] key, byte[] nonce, byte[] plain) {
        if (key.length != 32) throw new IllegalArgumentException("ключ 32 байта");
        if (nonce.length != NONCE) throw new IllegalArgumentException("nonce 24 байта");
        byte[] sub = hchacha20(key, nonce, 0);
        byte[] n12 = new byte[12];
        System.arraycopy(nonce, 16, n12, 4, 8);
        return chachaPoly(true, sub, n12, plain);
    }

    public static byte[] open(byte[] key, byte[] packed) {
        if (packed.length < NONCE + 16) throw new IllegalArgumentException("short ciphertext");
        byte[] nonce = new byte[NONCE];
        System.arraycopy(packed, 0, nonce, 0, NONCE);
        byte[] ct = new byte[packed.length - NONCE];
        System.arraycopy(packed, NONCE, ct, 0, ct.length);
        byte[] sub = hchacha20(key, nonce, 0);
        byte[] n12 = new byte[12];
        System.arraycopy(nonce, 16, n12, 4, 8);
        return chachaPoly(false, sub, n12, ct);
    }

    private static byte[] chachaPoly(boolean encrypt, byte[] key, byte[] nonce12, byte[] in) {
        try {
            ChaCha20Poly1305 aead = new ChaCha20Poly1305();
            aead.init(encrypt, new ParametersWithIV(new KeyParameter(key), nonce12));
            byte[] out = new byte[aead.getOutputSize(in.length)];
            int n = aead.processBytes(in, 0, in.length, out, 0);
            n += aead.doFinal(out, n);
            if (n == out.length) return out;
            byte[] trimmed = new byte[n];
            System.arraycopy(out, 0, trimmed, 0, n);
            return trimmed;
        } catch (InvalidCipherTextException e) {
            throw new IllegalArgumentException("бирка не сошлась");
        }
    }

    /** HChaCha20: 16-byte nonce at offset, no feed-forward, words 0-3 and 12-15. */
    static byte[] hchacha20(byte[] key, byte[] nonce, int off) {
        int[] s = new int[16];
        s[0] = 0x61707865;
        s[1] = 0x3320646e;
        s[2] = 0x79622d32;
        s[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) s[4 + i] = le32(key, i * 4);
        for (int i = 0; i < 4; i++) s[12 + i] = le32(nonce, off + i * 4);
        for (int i = 0; i < 10; i++) {
            quarter(s, 0, 4, 8, 12);
            quarter(s, 1, 5, 9, 13);
            quarter(s, 2, 6, 10, 14);
            quarter(s, 3, 7, 11, 15);
            quarter(s, 0, 5, 10, 15);
            quarter(s, 1, 6, 11, 12);
            quarter(s, 2, 7, 8, 13);
            quarter(s, 3, 4, 9, 14);
        }
        byte[] out = new byte[32];
        int[] idx = {0, 1, 2, 3, 12, 13, 14, 15};
        for (int i = 0; i < idx.length; i++) putLe32(out, i * 4, s[idx[i]]);
        return out;
    }

    private static void quarter(int[] s, int a, int b, int c, int d) {
        s[a] += s[b];
        s[d] = rotl(s[d] ^ s[a], 16);
        s[c] += s[d];
        s[b] = rotl(s[b] ^ s[c], 12);
        s[a] += s[b];
        s[d] = rotl(s[d] ^ s[a], 8);
        s[c] += s[d];
        s[b] = rotl(s[b] ^ s[c], 7);
    }

    private static int rotl(int x, int n) {
        return (x << n) | (x >>> (32 - n));
    }

    private static int le32(byte[] b, int o) {
        return (b[o] & 0xff) | ((b[o + 1] & 0xff) << 8) | ((b[o + 2] & 0xff) << 16) | ((b[o + 3] & 0xff) << 24);
    }

    private static void putLe32(byte[] b, int o, int v) {
        b[o] = (byte) v;
        b[o + 1] = (byte) (v >>> 8);
        b[o + 2] = (byte) (v >>> 16);
        b[o + 3] = (byte) (v >>> 24);
    }
}

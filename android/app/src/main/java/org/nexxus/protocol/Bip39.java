package org.nexxus.protocol;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class Bip39 {
    private static String[] words;
    private static Map<String, Integer> index;

    private Bip39() {}

    public static synchronized void load(InputStream in) {
        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String[] list = new String[2048];
            Map<String, Integer> map = new HashMap<String, Integer>();
            int n = 0;
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                if (n >= 2048) throw new IllegalArgumentException("лишние слова");
                list[n] = line;
                map.put(line, n);
                n++;
            }
            if (n != 2048) throw new IllegalArgumentException("слов " + n);
            words = list;
            index = map;
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String normalize(String phrase) {
        return phrase.trim().toLowerCase().replaceAll("\\s+", " ");
    }

    public static boolean valid(String phrase) {
        ensure();
        String n = normalize(phrase);
        String[] parts = n.split(" ");
        if (parts.length != 12) return false;
        int[] idx = new int[12];
        for (int i = 0; i < 12; i++) {
            Integer v = index.get(parts[i]);
            if (v == null) return false;
            idx[i] = v;
        }
        byte[] entropy = new byte[16];
        int acc = 0;
        int bits = 0;
        int ei = 0;
        for (int i = 0; i < 12; i++) {
            acc = ((acc & mask(bits)) << 11) | idx[i];
            bits += 11;
            while (bits >= 8 && ei < 16) {
                bits -= 8;
                entropy[ei++] = (byte) ((acc >> bits) & 0xff);
                acc &= mask(bits);
            }
        }
        if (ei != 16 || bits != 4) return false;
        int cs = (sha256(entropy)[0] >>> 4) & 0x0f;
        return (acc & 0x0f) == cs;
    }

    public static String generate() {
        ensure();
        byte[] ent = new byte[16];
        new SecureRandom().nextBytes(ent);
        return fromEntropy(ent);
    }

    static String fromEntropy(byte[] ent) {
        ensure();
        if (ent.length != 16) throw new IllegalArgumentException("entropy");
        int cs = (sha256(ent)[0] >>> 4) & 0x0f;
        int acc = 0;
        int bits = 0;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            acc = ((acc & mask(bits)) << 8) | (ent[i] & 0xff);
            bits += 8;
            bits = emitWords(sb, acc, bits);
            acc &= mask(bits);
        }
        acc = ((acc & mask(bits)) << 4) | cs;
        bits += 4;
        bits = emitWords(sb, acc, bits);
        if (bits != 0) throw new IllegalStateException("bip39 bits " + bits);
        return sb.toString();
    }

    private static int emitWords(StringBuilder sb, int acc, int bits) {
        while (bits >= 11) {
            bits -= 11;
            int w = (acc >> bits) & 0x7ff;
            if (sb.length() > 0) sb.append(' ');
            sb.append(words[w]);
            acc &= mask(bits);
        }
        return bits;
    }

    private static int mask(int bits) {
        if (bits <= 0) return 0;
        if (bits >= 31) return 0x7fffffff;
        return (1 << bits) - 1;
    }

    public static byte[] seed(String phrase) {
        if (!valid(phrase)) throw new IllegalArgumentException("Фраза BIP39 невалидна.");
        String n = normalize(phrase);
        return pbkdf2(Bytes.utf8(n), Bytes.utf8("mnemonic"), 2048, 64);
    }

    private static void ensure() {
        if (words == null) throw new IllegalStateException("словарь BIP39 не загружен");
    }

    private static byte[] sha256(byte[] in) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(in);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] pbkdf2(byte[] password, byte[] salt, int iterations, int dkLen) {
        try {
            Mac mac = Mac.getInstance("HmacSHA512");
            int hLen = 64;
            byte[] out = new byte[dkLen];
            byte[] block = new byte[salt.length + 4];
            System.arraycopy(salt, 0, block, 0, salt.length);
            int offset = 0;
            int blockIndex = 1;
            while (offset < dkLen) {
                block[salt.length] = (byte) (blockIndex >>> 24);
                block[salt.length + 1] = (byte) (blockIndex >>> 16);
                block[salt.length + 2] = (byte) (blockIndex >>> 8);
                block[salt.length + 3] = (byte) blockIndex;
                mac.init(new SecretKeySpec(password, "HmacSHA512"));
                byte[] u = mac.doFinal(block);
                byte[] t = u.clone();
                for (int i = 1; i < iterations; i++) {
                    mac.init(new SecretKeySpec(password, "HmacSHA512"));
                    u = mac.doFinal(u);
                    for (int k = 0; k < hLen; k++) t[k] ^= u[k];
                }
                int take = Math.min(hLen, dkLen - offset);
                System.arraycopy(t, 0, out, offset, take);
                offset += take;
                blockIndex++;
            }
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}

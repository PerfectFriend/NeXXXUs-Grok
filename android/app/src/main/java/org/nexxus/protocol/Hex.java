package org.nexxus.protocol;

public final class Hex {
    private Hex() {}

    public static String encode(byte[] data) {
        char[] out = new char[data.length * 2];
        char[] alphabet = "0123456789abcdef".toCharArray();
        for (int i = 0; i < data.length; i++) {
            int v = data[i] & 0xff;
            out[i * 2] = alphabet[v >>> 4];
            out[i * 2 + 1] = alphabet[v & 0x0f];
        }
        return new String(out);
    }

    public static byte[] decode(String hex) {
        String s = hex.trim().toLowerCase();
        if ((s.length() & 1) != 0) throw new IllegalArgumentException("нечётная hex-строка");
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = from(s.charAt(i * 2));
            int lo = from(s.charAt(i * 2 + 1));
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static int from(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        throw new IllegalArgumentException("не hex");
    }
}

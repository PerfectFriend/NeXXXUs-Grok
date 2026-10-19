package org.nexxus.protocol;

public final class B64 {
    private static final char[] T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

    private B64() {}

    public static String encode(byte[] data) {
        StringBuilder sb = new StringBuilder(((data.length + 2) / 3) * 4);
        int i = 0;
        while (i + 3 <= data.length) {
            int n = ((data[i] & 0xff) << 16) | ((data[i + 1] & 0xff) << 8) | (data[i + 2] & 0xff);
            sb.append(T[(n >>> 18) & 63]).append(T[(n >>> 12) & 63]).append(T[(n >>> 6) & 63]).append(T[n & 63]);
            i += 3;
        }
        int rem = data.length - i;
        if (rem == 1) {
            int n = (data[i] & 0xff) << 16;
            sb.append(T[(n >>> 18) & 63]).append(T[(n >>> 12) & 63]).append("==");
        } else if (rem == 2) {
            int n = ((data[i] & 0xff) << 16) | ((data[i + 1] & 0xff) << 8);
            sb.append(T[(n >>> 18) & 63]).append(T[(n >>> 12) & 63]).append(T[(n >>> 6) & 63]).append('=');
        }
        return sb.toString();
    }

    public static byte[] decode(String s) {
        String in = s.trim();
        int pad = 0;
        if (in.endsWith("==")) pad = 2;
        else if (in.endsWith("=")) pad = 1;
        int groups = in.length() / 4;
        byte[] out = new byte[groups * 3 - pad];
        int oi = 0;
        for (int g = 0; g < groups; g++) {
            int n = (val(in.charAt(g * 4)) << 18)
                    | (val(in.charAt(g * 4 + 1)) << 12)
                    | (val(in.charAt(g * 4 + 2)) << 6)
                    | val(in.charAt(g * 4 + 3));
            out[oi++] = (byte) ((n >>> 16) & 0xff);
            if (oi < out.length) out[oi++] = (byte) ((n >>> 8) & 0xff);
            if (oi < out.length) out[oi++] = (byte) (n & 0xff);
        }
        return out;
    }

    private static int val(char c) {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/' || c == '=') return 0;
        throw new IllegalArgumentException("не base64");
    }
}

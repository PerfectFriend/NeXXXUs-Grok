package org.nexxus.protocol;

import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** HKDF-SHA256, one block. Matches @noble/hashes hkdf(sha256, ikm, salt, info, 32). */
public final class Hkdf {
    private Hkdf() {}

    public static byte[] sha256(byte[] ikm, byte[] salt, byte[] info, int length) {
        if (length < 1 || length > 32) throw new IllegalArgumentException("hkdf length");
        try {
            byte[] saltBytes = (salt == null || salt.length == 0) ? new byte[32] : salt;
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(saltBytes, "HmacSHA256"));
            byte[] prk = mac.doFinal(ikm);
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            mac.update(info);
            mac.update((byte) 1);
            byte[] okm = mac.doFinal();
            byte[] out = new byte[length];
            System.arraycopy(okm, 0, out, 0, length);
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}

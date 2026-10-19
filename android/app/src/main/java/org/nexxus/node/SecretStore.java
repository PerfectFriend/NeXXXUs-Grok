package org.nexxus.node;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Mnemonic at rest, wrapped by a key that never leaves Android Keystore. */
public final class SecretStore {
    private static final String ALIAS = "nexxus-machine";
    private static final String FILE = "identity.bin";

    private SecretStore() {}

    public static String load(Context context) {
        File file = new File(context.getFilesDir(), FILE);
        if (!file.isFile()) return null;
        try {
            byte[] packed = read(file);
            if (packed.length < 13) return null;
            byte[] iv = new byte[12];
            System.arraycopy(packed, 0, iv, 0, 12);
            byte[] ct = new byte[packed.length - 12];
            System.arraycopy(packed, 12, ct, 0, ct.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, iv));
            return new String(cipher.doFinal(ct), "UTF-8");
        } catch (Exception e) {
            return null;
        }
    }

    public static void save(Context context, String mnemonic) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key());
            byte[] iv = cipher.getIV();
            byte[] ct = cipher.doFinal(mnemonic.getBytes("UTF-8"));
            byte[] packed = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, packed, 0, iv.length);
            System.arraycopy(ct, 0, packed, iv.length, ct.length);
            write(new File(context.getFilesDir(), FILE), packed);
        } catch (Exception e) {
            throw new IllegalStateException("не удалось закрыть фразу", e);
        }
    }

    private static SecretKey key() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (!ks.containsAlias(ALIAS)) {
            KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            kg.init(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build());
            kg.generateKey();
        }
        return (SecretKey) ks.getKey(ALIAS, null);
    }

    private static byte[] read(File file) throws Exception {
        FileInputStream in = new FileInputStream(file);
        try {
            byte[] buf = new byte[(int) file.length()];
            int o = 0;
            while (o < buf.length) {
                int n = in.read(buf, o, buf.length - o);
                if (n < 0) break;
                o += n;
            }
            return buf;
        } finally {
            in.close();
        }
    }

    private static void write(File file, byte[] data) throws Exception {
        FileOutputStream out = new FileOutputStream(file);
        try {
            out.write(data);
        } finally {
            out.close();
        }
    }
}

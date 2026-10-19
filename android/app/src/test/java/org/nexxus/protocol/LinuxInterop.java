package org.nexxus.protocol;

import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public final class LinuxInterop {
    public static void main(String[] args) throws Exception {
        Bip39.load(new FileInputStream(args[0]));
        String contact = new String(Files.readAllBytes(new File(args[1]).toPath()), StandardCharsets.UTF_8).trim();
        Contact linux = Identity.parseContact(contact);
        File dir = new File("/tmp/nxx-android-interop");
        delete(dir);
        dir.mkdirs();
        Identity me = Identity.derive(Bip39.generate());
        NodeSession node = new NodeSession(me, dir);
        try {
            node.listen("127.0.0.1", 19221, "127.0.0.1", "android");
            node.addContact(contact);
            for (int i = 0; i < 50; i++) {
                boolean on = false;
                for (Contact c : node.snapshotContacts()) {
                    if (c.fingerprint.equals(linux.fingerprint) && c.online) on = true;
                }
                if (on) break;
                Thread.sleep(100);
                if (i == 49) throw new IllegalStateException("linux offline");
            }
            node.sendChat(linux.fingerprint, "android-hi");
            String got = null;
            for (int i = 0; i < 50; i++) {
                for (ChatLine m : node.snapshotMessages()) {
                    if (!m.fromMe && m.text.startsWith("linux-pong:")) got = m.text;
                }
                for (VaultFile f : node.snapshotFiles()) {
                    if ("from-linux.txt".equals(f.name)) {
                        String body = new String(node.loadPlain(f.id), StandardCharsets.UTF_8);
                        if (!"linux-file-ok".equals(body)) throw new IllegalStateException(body);
                        if (got != null) {
                            System.out.println("LINUX INTEROP OK " + got);
                            return;
                        }
                    }
                }
                Thread.sleep(100);
            }
            throw new IllegalStateException("timeout pong=" + got);
        } finally {
            node.stop();
        }
    }

    private static void delete(File f) {
        if (f == null || !f.exists()) return;
        if (f.isDirectory()) {
            File[] kids = f.listFiles();
            if (kids != null) for (File k : kids) delete(k);
        }
        f.delete();
    }
}

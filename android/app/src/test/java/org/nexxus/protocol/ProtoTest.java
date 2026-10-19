package org.nexxus.protocol;

import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public final class ProtoTest {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) throw new IllegalArgumentException("words vectors");
        Bip39.load(new FileInputStream(args[0]));
        String json = new String(java.nio.file.Files.readAllBytes(new File(args[1]).toPath()), StandardCharsets.UTF_8);
        @SuppressWarnings("unchecked")
        Map<String, Object> vec = (Map<String, Object>) Json.parse(json);

        byte[] alice = Hex.decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] bob = Hex.decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        eq("alice pub", Hex.encode(Identity.x25519Public(alice)), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        eq("shared", Hex.encode(Identity.dh(alice, Identity.x25519Public(bob))), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        String phrase = Json.str(vec, "phrase");
        if (!Bip39.valid(phrase)) throw new IllegalStateException("phrase invalid");
        Identity id = Identity.derive(phrase);
        eq("fp", id.fingerprint, Json.str(vec, "fp"));
        eq("xPub", id.pubHex, Json.str(vec, "xPub"));
        eq("xPriv", Hex.encode(id.xPriv), Json.str(vec, "xPriv"));
        eq("edPub", id.edHex, Json.str(vec, "edPub"));
        eq("edPriv", Hex.encode(id.edPriv), Json.str(vec, "edPriv"));
        eq("vault", Hex.encode(id.vaultKey), Json.str(vec, "vault"));
        eq("seed", Hex.encode(id.seed), Json.str(vec, "seed"));

        Identity id2 = Identity.derive(Json.str(vec, "phrase2"));
        eq("fp2", id2.fingerprint, Json.str(vec, "fp2"));

        Identity.Eph eph = Identity.ephFromSecret(Hex.decode(Json.str(vec, "ephPriv")));
        eq("ephPub", eph.pubHex, Json.str(vec, "ephPub"));
        Map<String, Object> hello = id.signHello(eph.pubHex, "alpha", "10.0.0.8", 4377);
        Identity.verifyHello(hello);
        @SuppressWarnings("unchecked")
        Map<String, Object> expectedHello = (Map<String, Object>) vec.get("hello");
        eq("sig", Json.str(hello, "sig"), Json.str(expectedHello, "sig"));

        byte[] session = Identity.sessionKey(
                id.xPriv, id.xPub, Hex.decode(Json.str(vec, "ephPriv")),
                id2.xPub, Hex.decode(Json.str(vec, "ephPub2")), true);
        byte[] session2 = Identity.sessionKey(
                id2.xPriv, id2.xPub, Hex.decode(Json.str(vec, "ephPriv2")),
                id.xPub, eph.pub, false);
        eq("session", Hex.encode(session), Json.str(vec, "session"));
        eq("session sym", Hex.encode(session), Hex.encode(session2));

        byte[] ct = Aead.sealWithNonce(session, Hex.decode(Json.str(vec, "fixedNonce")), Bytes.utf8("привет-nexxus"));
        eq("aead", Hex.encode(ct), Json.str(vec, "fixedCt"));
        byte[] opened = Aead.open(session, Hex.decode(Json.str(vec, "aead")));
        eq("aead open", Bytes.utf8(opened), "привет-nexxus");

        try {
            Identity.parseContact("nexxus:1:" + id2.fingerprint + ":" + id.pubHex + "@127.0.0.1:4377");
            throw new IllegalStateException("mixed contact accepted");
        } catch (IllegalArgumentException expected) {
            if (!expected.getMessage().contains("Отпечаток")) throw expected;
        }

        mesh();
        System.out.println("PROTO OK");
    }

    private static void mesh() throws Exception {
        File d1 = new File("/tmp/nxx-j-a");
        File d2 = new File("/tmp/nxx-j-b");
        delete(d1);
        delete(d2);
        d1.mkdirs();
        d2.mkdirs();
        Identity a = Identity.derive(Bip39.generate());
        Identity b = Identity.derive(Bip39.generate());
        NodeSession n1 = new NodeSession(a, d1);
        NodeSession n2 = new NodeSession(b, d2);
        try {
            n1.listen("127.0.0.1", 19111, "127.0.0.1", "alpha");
            n2.listen("127.0.0.1", 19121, "127.0.0.1", "beta");
            n2.addContact(n1.contactUri());
            waitUntil("online", new Check() {
                public boolean ok() {
                    boolean bSees = false;
                    boolean aSees = false;
                    for (Contact c : n2.snapshotContacts()) if (c.fingerprint.equals(a.fingerprint) && c.online) bSees = true;
                    for (Contact c : n1.snapshotContacts()) if (c.fingerprint.equals(b.fingerprint) && c.online) aSees = true;
                    return bSees && aSees;
                }
            });
            n2.sendChat(a.fingerprint, "привет от java");
            waitUntil("chat", new Check() {
                public boolean ok() {
                    for (ChatLine m : n1.snapshotMessages()) {
                        if ("привет от java".equals(m.text) && !m.fromMe) return true;
                    }
                    return false;
                }
            });
            VaultFile rec = n2.storePlain("hello.txt", Bytes.utf8("nexxus-payload-ok"));
            n2.sendFile(a.fingerprint, rec.id);
            waitUntil("file", new Check() {
                public boolean ok() {
                    for (VaultFile f : n1.snapshotFiles()) if ("hello.txt".equals(f.name)) return true;
                    return false;
                }
            });
            String got = null;
            for (VaultFile f : n1.snapshotFiles()) {
                if ("hello.txt".equals(f.name)) got = Bytes.utf8(n1.loadPlain(f.id));
            }
            eq("file", got, "nexxus-payload-ok");
        } finally {
            n1.stop();
            n2.stop();
        }
    }

    interface Check { boolean ok(); }

    private static void waitUntil(String label, Check check) throws InterruptedException {
        for (int i = 0; i < 50; i++) {
            if (check.ok()) return;
            Thread.sleep(100);
        }
        throw new IllegalStateException("timeout " + label);
    }

    private static void eq(String name, String a, String b) {
        if (a == null || !a.equals(b)) throw new IllegalStateException(name + "\n " + a + "\n " + b);
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

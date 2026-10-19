package org.nexxus.protocol;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

public final class Identity {
    public final String mnemonic;
    public final byte[] seed;
    public final byte[] xPriv;
    public final byte[] xPub;
    public final byte[] edPriv;
    public final byte[] edPub;
    public final byte[] vaultKey;
    public final String fingerprint;
    public final String pubHex;
    public final String edHex;

    private Identity(String mnemonic, byte[] seed, byte[] xPriv, byte[] xPub, byte[] edPriv, byte[] edPub, byte[] vaultKey) {
        this.mnemonic = mnemonic;
        this.seed = seed;
        this.xPriv = xPriv;
        this.xPub = xPub;
        this.edPriv = edPriv;
        this.edPub = edPub;
        this.vaultKey = vaultKey;
        this.fingerprint = fingerprintFromPub(xPub);
        this.pubHex = Hex.encode(xPub);
        this.edHex = Hex.encode(edPub);
    }

    public static Identity derive(String phrase) {
        String mnemonic = Bip39.normalize(phrase);
        byte[] seed = Bip39.seed(mnemonic);
        byte[] xPriv = Hkdf.sha256(seed, Bytes.utf8("nexxus-x25519"), Bytes.utf8("v1"), 32);
        byte[] edPriv = Hkdf.sha256(seed, Bytes.utf8("nexxus-ed25519"), Bytes.utf8("v1"), 32);
        byte[] vault = Hkdf.sha256(seed, Bytes.utf8("nexxus-vault"), Bytes.utf8("v1"), 32);
        return new Identity(mnemonic, seed, xPriv, x25519Public(xPriv), edPriv, ed25519Public(edPriv), vault);
    }

    public static String fingerprintFromPub(byte[] pub) {
        try {
            byte[] dig = MessageDigest.getInstance("SHA-256").digest(pub);
            return "nxx1" + Hex.encode(dig).substring(0, 16);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String fingerprintFromPub(String pubHex) {
        return fingerprintFromPub(Hex.decode(pubHex));
    }

    public static final class Eph {
        public final byte[] secret;
        public final byte[] pub;
        public final String pubHex;
        Eph(byte[] secret, byte[] pub) {
            this.secret = secret;
            this.pub = pub;
            this.pubHex = Hex.encode(pub);
        }
    }

    public static Eph generateEph() {
        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);
        return new Eph(secret, x25519Public(secret));
    }

    public static Eph ephFromSecret(byte[] secret) {
        return new Eph(secret, x25519Public(secret));
    }

    public static byte[] sessionKey(byte[] myStaticPriv, byte[] myStaticPub, byte[] myEphPriv,
                                     byte[] theirStaticPub, byte[] theirEphPub, boolean initiator) {
        byte[] ss = dh(myStaticPriv, theirStaticPub);
        byte[] ee = dh(myEphPriv, theirEphPub);
        byte[] es = initiator ? dh(myEphPriv, theirStaticPub) : dh(myStaticPriv, theirEphPub);
        byte[] se = initiator ? dh(myStaticPriv, theirEphPub) : dh(myEphPriv, theirStaticPub);
        byte[] ikm = Bytes.concat(ss, ee, es, se);
        String a = Hex.encode(myStaticPub);
        String b = Hex.encode(theirStaticPub);
        byte[] p1 = a.compareTo(b) < 0 ? myStaticPub : theirStaticPub;
        byte[] p2 = a.compareTo(b) < 0 ? theirStaticPub : myStaticPub;
        byte[] salt = Bytes.concat(Bytes.utf8("nexxus-session"), p1, p2);
        return Hkdf.sha256(ikm, salt, Bytes.utf8("nxxp2"), 32);
    }

    public Map<String, Object> signHello(String ephHex, String name, String host, int port) {
        Map<String, Object> body = new LinkedHashMap<String, Object>();
        body.put("v", Integer.valueOf(3));
        body.put("t", "hello");
        body.put("fp", fingerprint);
        body.put("pub", pubHex);
        body.put("eph", ephHex);
        body.put("ed", edHex);
        body.put("name", name == null ? "" : name);
        body.put("host", host == null ? "" : host);
        body.put("port", Integer.valueOf(port));
        body.put("sig", Hex.encode(ed25519Sign(edPriv, helloCanon(body))));
        return body;
    }

    public static void verifyHello(Map<String, Object> msg) {
        if (msg == null || !"hello".equals(Json.str(msg, "t"))) throw new IllegalArgumentException("нет hello");
        if (Json.num(msg, "v") != 3) throw new IllegalArgumentException("нужна нода 0.1.2 (рукопожатие v3)");
        String pub = Json.str(msg, "pub");
        String eph = Json.str(msg, "eph");
        String ed = Json.str(msg, "ed");
        String sig = Json.str(msg, "sig");
        if (!isHex(pub.toLowerCase(), 32) || !isHex(eph.toLowerCase(), 32) || !isHex(ed.toLowerCase(), 32) || !isHex(sig.toLowerCase(), 64)) {
            throw new IllegalArgumentException("битые поля hello");
        }
        String fp = Json.str(msg, "fp");
        if (!fingerprintFromPub(pub).equals(fp.toLowerCase())) {
            throw new IllegalArgumentException("отпечаток не от этого X25519 ключа");
        }
        if (!ed25519Verify(Hex.decode(ed), helloCanon(msg), Hex.decode(sig))) {
            throw new IllegalArgumentException("подпись hello не сходится");
        }
    }

    public static byte[] helloCanon(Map<String, Object> msg) {
        String canon = Json.num(msg, "v")
                + "|" + Json.str(msg, "t")
                + "|" + Json.str(msg, "fp")
                + "|" + Json.str(msg, "pub")
                + "|" + Json.str(msg, "eph")
                + "|" + Json.str(msg, "ed")
                + "|" + Json.str(msg, "name")
                + "|" + Json.str(msg, "host")
                + "|" + Json.num(msg, "port");
        return Bytes.utf8(canon);
    }

    private static final Pattern CONTACT = Pattern.compile(
            "^nexxus:1:(nxx1[a-f0-9]+):([a-f0-9]{64})@([^:@\\s]+):(\\d{1,5})$",
            Pattern.CASE_INSENSITIVE);

    public static String formatContact(String fingerprint, String pubHex, String host, int port) {
        return "nexxus:1:" + fingerprint + ":" + pubHex + "@" + host + ":" + port;
    }

    public static Contact parseContact(String uri) {
        Matcher m = CONTACT.matcher(uri == null ? "" : uri.trim());
        if (!m.matches()) throw new IllegalArgumentException("Контакт должен выглядеть как nexxus:1:nxx1…:ключ@хост:порт");
        int port = Integer.parseInt(m.group(4));
        if (port < 1 || port > 65535) throw new IllegalArgumentException("Некорректный порт в контакте.");
        String fp = m.group(1).toLowerCase();
        String pub = m.group(2).toLowerCase();
        if (!fingerprintFromPub(pub).equals(fp)) throw new IllegalArgumentException("Отпечаток не совпадает с публичным ключом.");
        return new Contact(fp, pub, m.group(3), port, fp);
    }

    public static byte[] x25519Public(byte[] secret) {
        return new X25519PrivateKeyParameters(secret, 0).generatePublicKey().getEncoded();
    }

    public static byte[] dh(byte[] secret, byte[] theirPub) {
        X25519Agreement agr = new X25519Agreement();
        agr.init(new X25519PrivateKeyParameters(secret, 0));
        byte[] out = new byte[32];
        agr.calculateAgreement(new X25519PublicKeyParameters(theirPub, 0), out, 0);
        return out;
    }

    public static byte[] ed25519Public(byte[] seed) {
        return new Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().getEncoded();
    }

    public static byte[] ed25519Sign(byte[] seed, byte[] message) {
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, new Ed25519PrivateKeyParameters(seed, 0));
        signer.update(message, 0, message.length);
        return signer.generateSignature();
    }

    public static boolean ed25519Verify(byte[] pub, byte[] message, byte[] sig) {
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(false, new Ed25519PublicKeyParameters(pub, 0));
        signer.update(message, 0, message.length);
        return signer.verifySignature(sig);
    }

    private static boolean isHex(String s, int bytes) {
        return s != null && s.matches("^[a-f0-9]{" + (bytes * 2) + "}$");
    }
}

package org.nexxus.node;

import android.content.Context;
import java.io.File;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Enumeration;
import org.nexxus.protocol.Bip39;
import org.nexxus.protocol.Identity;
import org.nexxus.protocol.NodeSession;

public final class Engine {
    private static Engine instance;
    private final Context app;
    private NodeSession session;
    private String mnemonic;
    private boolean booted;

    private Engine(Context app) {
        this.app = app.getApplicationContext();
    }

    public static synchronized Engine get(Context context) {
        if (instance == null) instance = new Engine(context);
        return instance;
    }

    public synchronized void boot() {
        if (booted) return;
        try {
            Bip39.load(app.getAssets().open("bip39-english.txt"));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        String saved = SecretStore.load(app);
        boolean fresh = saved == null || !Bip39.valid(saved);
        mnemonic = fresh ? Bip39.generate() : saved;
        if (fresh) SecretStore.save(app, mnemonic);
        session = new NodeSession(Identity.derive(mnemonic), new File(app.getFilesDir(), "node"));
        booted = true;
    }

    public synchronized NodeSession session() {
        if (!booted) boot();
        return session;
    }

    public synchronized String mnemonic() {
        return mnemonic;
    }

    public synchronized void listen(String host, int port) throws Exception {
        if (!booted) boot();
        String adv = host == null || host.trim().isEmpty() ? lanIp() : host.trim();
        session.listen("0.0.0.0", port, adv, "android");
    }

    public static String lanIp() {
        try {
            Enumeration<NetworkInterface> ifs = NetworkInterface.getNetworkInterfaces();
            while (ifs.hasMoreElements()) {
                NetworkInterface nif = ifs.nextElement();
                if (!nif.isUp() || nif.isLoopback()) continue;
                Enumeration<InetAddress> addrs = nif.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress a = addrs.nextElement();
                    if (a instanceof Inet4Address && !a.isLoopbackAddress()) return a.getHostAddress();
                }
            }
        } catch (Exception ignored) {}
        return "127.0.0.1";
    }
}

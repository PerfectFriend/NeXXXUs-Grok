package org.nexxus.node;

import android.Manifest;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.core.content.FileProvider;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.List;
import org.nexxus.protocol.ChatLine;
import org.nexxus.protocol.Contact;
import org.nexxus.protocol.NodeSession;
import org.nexxus.protocol.VaultFile;

public class MainActivity extends AppCompatActivity {
    private final Handler main = new Handler(Looper.getMainLooper());
    private String activeFp;
    private ActivityResultLauncher<String[]> picker;
    private boolean seedAck;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        seedAck = getSharedPreferences("nexxus", MODE_PRIVATE).getBoolean("seedAck", false);
        picker = registerForActivityResult(new ActivityResultContracts.OpenDocument(), this::onPicked);
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 7);
        }
        EditText host = findViewById(R.id.host);
        if (host.getText().length() == 0) host.setText(Engine.lanIp());
        findViewById(R.id.listen).setOnClickListener(v -> listen());
        findViewById(R.id.copy).setOnClickListener(v -> copyContact());
        findViewById(R.id.reveal).setOnClickListener(v -> reveal());
        findViewById(R.id.seedOk).setOnClickListener(v -> ackSeed());
        findViewById(R.id.add).setOnClickListener(v -> addContact());
        findViewById(R.id.send).setOnClickListener(v -> sendChat());
        findViewById(R.id.pickFile).setOnClickListener(v -> picker.launch(new String[]{"*/*"}));
        new Thread(() -> {
            try {
                Engine.get(this).boot();
                main.post(this::render);
            } catch (RuntimeException e) {
                main.post(() -> ((TextView) findViewById(R.id.status)).setText(e.getMessage()));
            }
        }, "nexxus-boot-ui").start();
        main.postDelayed(this::tick, 800);
    }

    private void tick() {
        render();
        main.postDelayed(this::tick, 1000);
    }

    private void listen() {
        EditText host = findViewById(R.id.host);
        EditText portField = findViewById(R.id.port);
        int port;
        try {
            port = Integer.parseInt(portField.getText().toString().trim());
        } catch (NumberFormatException e) {
            ((TextView) findViewById(R.id.status)).setText("Порт — число 1–65535.");
            return;
        }
        Intent intent = new Intent(this, MeshService.class);
        intent.putExtra(MeshService.EXTRA_HOST, host.getText().toString().trim());
        intent.putExtra(MeshService.EXTRA_PORT, port);
        ContextCompat.startForegroundService(this, intent);
        ((TextView) findViewById(R.id.status)).setText("Поднимаем прослушивание. Держите телефон на зарядке и в Wi-Fi.");
        try {
            Intent battery = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:" + getPackageName()));
            startActivity(battery);
        } catch (RuntimeException ignored) {}
    }

    private void copyContact() {
        NodeSession session = safeSession();
        if (session == null) return;
        ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        clipboard.setPrimaryClip(ClipData.newPlainText("nexxus", session.contactUri()));
        Toast.makeText(this, "Контакт скопирован", Toast.LENGTH_SHORT).show();
    }

    private void reveal() {
        String phrase = Engine.get(this).mnemonic();
        if (phrase == null) return;
        new AlertDialog.Builder(this)
                .setTitle("Фраза BIP39")
                .setMessage(phrase)
                .setPositiveButton("Закрыть", null)
                .show();
    }

    private void ackSeed() {
        seedAck = true;
        getSharedPreferences("nexxus", MODE_PRIVATE).edit().putBoolean("seedAck", true).apply();
        findViewById(R.id.seedCard).setVisibility(View.GONE);
    }

    private void addContact() {
        TextView err = findViewById(R.id.addErr);
        err.setText("");
        NodeSession session = safeSession();
        if (session == null) return;
        EditText uri = findViewById(R.id.uri);
        try {
            Contact row = session.addContact(uri.getText().toString());
            activeFp = row.fingerprint;
            uri.setText("");
        } catch (RuntimeException e) {
            err.setText(e.getMessage());
        }
        render();
    }

    private void sendChat() {
        TextView err = findViewById(R.id.chatErr);
        err.setText("");
        NodeSession session = safeSession();
        if (session == null) return;
        if (activeFp == null) {
            err.setText("Сначала выберите контакт.");
            return;
        }
        EditText input = findViewById(R.id.chatInput);
        try {
            session.sendChat(activeFp, input.getText().toString());
            input.setText("");
        } catch (RuntimeException e) {
            err.setText(e.getMessage());
        }
        render();
    }

    private void onPicked(Uri uri) {
        if (uri == null) return;
        NodeSession session = safeSession();
        if (session == null) return;
        try {
            InputStream in = getContentResolver().openInputStream(uri);
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] tmp = new byte[8192];
            int n;
            int total = 0;
            while ((n = in.read(tmp)) >= 0) {
                total += n;
                if (total > 32 * 1024 * 1024) throw new IllegalArgumentException("Файл больше 32 МБ.");
                buf.write(tmp, 0, n);
            }
            in.close();
            String name = "file.bin";
            VaultFile rec = session.storePlain(name, buf.toByteArray());
            if (activeFp != null) session.sendFile(activeFp, rec.id);
            Toast.makeText(this, activeFp == null ? "В сейфе" : "Отправлен", Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            ((TextView) findViewById(R.id.chatErr)).setText(e.getMessage());
        }
        render();
    }

    private void render() {
        NodeSession session = safeSession();
        if (session == null) return;
        ((TextView) findViewById(R.id.fp)).setText(session.identity.fingerprint + "  ·  beta 0.1.2");
        ((TextView) findViewById(R.id.contact)).setText(session.contactUri());
        View seed = findViewById(R.id.seedCard);
        if (!seedAck) {
            seed.setVisibility(View.VISIBLE);
            ((TextView) findViewById(R.id.words)).setText(Engine.get(this).mnemonic());
        } else {
            seed.setVisibility(View.GONE);
        }
        List<Contact> peers = session.snapshotContacts();
        if (activeFp == null && !peers.isEmpty()) activeFp = peers.get(0).fingerprint;
        LinearLayout box = findViewById(R.id.peers);
        box.removeAllViews();
        Contact selected = null;
        for (Contact peer : peers) {
            if (peer.fingerprint.equals(activeFp)) selected = peer;
            Button button = new Button(this);
            button.setAllCaps(false);
            button.setText((peer.online ? "● " : "○ ") + peer.name + "\n" + peer.host + ":" + peer.port);
            button.setBackgroundResource(R.drawable.btn_ghost);
            button.setTextColor(0xFFF4F4F2);
            button.setOnClickListener(v -> {
                activeFp = peer.fingerprint;
                render();
            });
            box.addView(button);
        }
        if (peers.isEmpty()) {
            TextView empty = new TextView(this);
            empty.setText("Пока никого. Вставьте контакт Linux-ноды или второго телефона.");
            empty.setTextColor(0xFF8C8C86);
            box.addView(empty);
        }
        ((TextView) findViewById(R.id.chatTitle)).setText(selected == null ? "Нет диалога" : selected.name + (selected.online ? "" : " · офлайн"));
        StringBuilder thread = new StringBuilder();
        for (ChatLine line : session.snapshotMessages()) {
            if (activeFp != null && activeFp.equals(line.fp)) {
                thread.append(line.fromMe ? "вы: " : "он: ").append(line.text).append("\n");
            }
        }
        ((TextView) findViewById(R.id.thread)).setText(thread.length() == 0 ? "Тишина." : thread.toString());
        LinearLayout files = findViewById(R.id.files);
        files.removeAllViews();
        for (VaultFile file : session.snapshotFiles()) {
            Button row = new Button(this);
            row.setAllCaps(false);
            row.setText(file.name + "  ·  " + file.chunks + " × 16 КБ");
            row.setBackgroundResource(R.drawable.btn_ghost);
            row.setTextColor(0xFFF4F4F2);
            row.setOnClickListener(v -> share(file));
            files.addView(row);
        }
        StringBuilder log = new StringBuilder();
        int shown = 0;
        for (String line : session.snapshotLog()) {
            log.append(line).append("\n");
            if (++shown >= 8) break;
        }
        ((TextView) findViewById(R.id.log)).setText(log.toString());
    }

    private void share(VaultFile file) {
        NodeSession session = safeSession();
        if (session == null) return;
        try {
            File dir = new File(getCacheDir(), "share");
            if (!dir.isDirectory()) dir.mkdirs();
            File out = new File(dir, file.name.replace("/", ""));
            FileOutputStream stream = new FileOutputStream(out);
            stream.write(session.loadPlain(file.id));
            stream.close();
            Uri uri = FileProvider.getUriForFile(this, getPackageName() + ".files", out);
            Intent send = new Intent(Intent.ACTION_SEND);
            send.setType("application/octet-stream");
            send.putExtra(Intent.EXTRA_STREAM, uri);
            send.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(Intent.createChooser(send, "Файл из сейфа"));
        } catch (Exception e) {
            Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private NodeSession safeSession() {
        try {
            return Engine.get(this).session();
        } catch (RuntimeException e) {
            return null;
        }
    }
}

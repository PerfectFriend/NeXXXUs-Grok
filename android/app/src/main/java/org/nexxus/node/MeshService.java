package org.nexxus.node;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;
import androidx.core.app.NotificationCompat;

public class MeshService extends Service {
    public static final String EXTRA_HOST = "host";
    public static final String EXTRA_PORT = "port";
    private static final String CHANNEL = "nexxus-mesh";
    private static final int NOTE_ID = 7;
    private PowerManager.WakeLock wakeLock;

    @Override
    public void onCreate() {
        super.onCreate();
        PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "nexxus:mesh");
        wakeLock.setReferenceCounted(false);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Notification note = buildNote("Нода поднимается");
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(NOTE_ID, note, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
        } else {
            startForeground(NOTE_ID, note);
        }
        if (!wakeLock.isHeld()) wakeLock.acquire();
        final String host = intent != null ? intent.getStringExtra(EXTRA_HOST) : null;
        final int port = intent != null && intent.hasExtra(EXTRA_PORT) ? intent.getIntExtra(EXTRA_PORT, 4377) : 4377;
        new Thread(new Runnable() {
            @Override public void run() {
                try {
                    Engine.get(MeshService.this).listen(host, port);
                    notifyNow("Слушает TCP " + port);
                } catch (Exception e) {
                    notifyNow("Не поднялась: " + e.getMessage());
                }
            }
        }, "nexxus-boot").start();
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
        Engine engine = Engine.get(this);
        try {
            engine.session().stop();
        } catch (RuntimeException ignored) {}
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void notifyNow(String text) {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        nm.notify(NOTE_ID, buildNote(text));
    }

    private Notification buildNote(String text) {
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel channel = new NotificationChannel(CHANNEL, "NeXXUs", NotificationManager.IMPORTANCE_LOW);
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            nm.createNotificationChannel(channel);
        }
        Intent open = new Intent(this, MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE);
        return new NotificationCompat.Builder(this, CHANNEL)
                .setSmallIcon(android.R.drawable.stat_sys_download_done)
                .setContentTitle("NeXXUs")
                .setContentText(text)
                .setContentIntent(pi)
                .setOngoing(true)
                .build();
    }
}

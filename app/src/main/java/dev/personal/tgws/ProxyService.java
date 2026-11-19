package dev.personal.tgws;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.graphics.drawable.Icon;
import android.os.IBinder;
import android.os.PowerManager;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import dev.personal.tgws.core.ProxyLog;
import dev.personal.tgws.core.ProxyServer;
import dev.personal.tgws.core.ProxySettings;

/** Foreground service that owns the local proxy. */
public class ProxyService extends Service {

    static final String ACTION_START = "dev.personal.tgws.START";
    static final String ACTION_STOP = "dev.personal.tgws.STOP";
    static final String ACTION_RESTART = "dev.personal.tgws.RESTART";

    private static final String CHANNEL_ID = "proxy";
    private static final int NOTIFICATION_ID = 1;

    /** Start/stop work happens off the main thread, one task at a time. */
    private static final ExecutorService CONTROL = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "tgws-control");
        t.setDaemon(true);
        return t;
    });

    private PowerManager.WakeLock wakeLock;

    static void start(Context c) {
        c.startForegroundService(new Intent(c, ProxyService.class).setAction(ACTION_START));
    }

    static void stop(Context c) {
        c.startForegroundService(new Intent(c, ProxyService.class).setAction(ACTION_STOP));
    }

    static void restart(Context c) {
        c.startForegroundService(new Intent(c, ProxyService.class).setAction(ACTION_RESTART));
    }

    @Override
    public void onCreate() {
        super.onCreate();
        LogBuffer.install();
        NotificationChannel channel = new NotificationChannel(
            CHANNEL_ID, getString(R.string.notif_channel), NotificationManager.IMPORTANCE_LOW);
        getSystemService(NotificationManager.class).createNotificationChannel(channel);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = (intent != null) ? intent.getAction() : ACTION_START; // null = restarted by the system

        // Every start request must be answered with startForeground(), even when we are about to stop.
        try {
            startForeground(NOTIFICATION_ID, buildNotification(),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } catch (RuntimeException e) {
            LogBuffer.add("E cannot enter foreground: " + e);
            ProxyRuntime.set(ProxyRuntime.Status.FAILED, String.valueOf(e.getMessage()));
            stopSelf();
            return START_NOT_STICKY;
        }

        if (ACTION_STOP.equals(action)) {
            CONTROL.execute(this::stopServer);
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelf();
            return START_NOT_STICKY;
        }
        if (ACTION_RESTART.equals(action)) {
            CONTROL.execute(() -> {
                stopServer();
                startServer();
            });
        } else {
            CONTROL.execute(() -> {
                if (ProxyRuntime.server() == null) {
                    startServer();
                }
            });
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        CONTROL.execute(this::stopServer);
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    // ---- server lifecycle (runs on CONTROL) --------------------------------------------------

    private void startServer() {
        ProxyRuntime.set(ProxyRuntime.Status.STARTING, "");
        refreshNotification();

        ProxyConfig cfg = new ProxyConfig(this);
        ProxyLog.verbose = cfg.verbose();

        ProxySettings settings;
        try {
            settings = cfg.toSettings();
        } catch (IllegalArgumentException e) {
            fail("Invalid settings: " + e.getMessage());
            return;
        }

        ProxyServer server = new ProxyServer(settings);
        try {
            server.start();
        } catch (IOException e) {
            server.stop();
            fail("Cannot listen on " + settings.host + ":" + settings.port + " (" + e.getMessage() + ")");
            return;
        }
        ProxyRuntime.setServer(server);
        acquireWakeLock();
        ProxyRuntime.set(ProxyRuntime.Status.RUNNING, settings.host + ":" + settings.port);
        refreshNotification();
    }

    private void stopServer() {
        ProxyServer server = ProxyRuntime.server();
        ProxyRuntime.setServer(null);
        if (server != null) {
            server.stop();
            LogBuffer.add("I Proxy stopped");
        }
        releaseWakeLock();
        if (ProxyRuntime.status() != ProxyRuntime.Status.FAILED) {
            ProxyRuntime.set(ProxyRuntime.Status.STOPPED, "");
        }
    }

    private void fail(String message) {
        LogBuffer.add("E " + message);
        ProxyRuntime.set(ProxyRuntime.Status.FAILED, message);
        releaseWakeLock();
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    private void acquireWakeLock() {
        if (wakeLock == null) {
            PowerManager pm = getSystemService(PowerManager.class);
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "tgws:proxy");
            wakeLock.setReferenceCounted(false);
        }
        if (!wakeLock.isHeld()) {
            wakeLock.acquire();
        }
    }

    private void releaseWakeLock() {
        if (wakeLock != null && wakeLock.isHeld()) {
            wakeLock.release();
        }
    }

    // ---- notification ------------------------------------------------------------------------

    private void refreshNotification() {
        getSystemService(NotificationManager.class).notify(NOTIFICATION_ID, buildNotification());
    }

    private Notification buildNotification() {
        String text;
        switch (ProxyRuntime.status()) {
            case RUNNING:
                text = getString(R.string.notif_running, ProxyRuntime.detail());
                break;
            case FAILED:
                text = ProxyRuntime.detail();
                break;
            default:
                text = getString(R.string.status_starting);
                break;
        }

        PendingIntent open = PendingIntent.getActivity(
            this, 0, new Intent(this, MainActivity.class),
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        PendingIntent stop = PendingIntent.getForegroundService(
            this, 1, new Intent(this, ProxyService.class).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        return new Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(open)
            .setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
            .addAction(new Notification.Action.Builder(
                Icon.createWithResource(this, R.drawable.ic_notification),
                getString(R.string.notif_stop), stop).build())
            .build();
    }
}

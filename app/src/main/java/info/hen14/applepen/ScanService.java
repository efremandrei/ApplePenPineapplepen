package info.hen14.applepen;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;
import info.hen14.applepen.core.ScanConfig;
import info.hen14.applepen.core.AuthCredentials;
import info.hen14.applepen.core.ScanEngine;
import info.hen14.applepen.core.ScanReport;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class ScanService extends Service {
    public static final String START = "info.hen14.applepen.START", CANCEL = "info.hen14.applepen.CANCEL";
    public static final State state = new State();
    public static final class State {
        public volatile boolean running;
        public volatile int completed, total;
        public volatile String message = "Ready", persistenceError = "";
        public volatile ScanReport report;
    }
    private ScanEngine engine;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private NotificationManager notifications;
    private long lastNotification;
    private PowerManager.WakeLock wakeLock;
    private static AuthCredentials pendingCredentials;
    static synchronized void prepareCredentials(AuthCredentials credentials) {
        if (pendingCredentials != null) pendingCredentials.close(); pendingCredentials = credentials;
    }
    private static synchronized AuthCredentials takeCredentials() { AuthCredentials result = pendingCredentials; pendingCredentials = null; return result; }
    @Override public void onCreate() {
        super.onCreate();
        notifications = getSystemService(NotificationManager.class);
        notifications.createNotificationChannel(new NotificationChannel("scan", "Scan progress", NotificationManager.IMPORTANCE_LOW));
    }
    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) { stopSelf(); return START_NOT_STICKY; }
        if (CANCEL.equals(intent.getAction())) { if (engine != null) { state.message = "Stopping scan…"; engine.cancel(); } else stopSelf(); return START_NOT_STICKY; }
        if (!START.equals(intent.getAction()) || state.running) return START_NOT_STICKY;
        ScanConfig config;
        if (Build.VERSION.SDK_INT >= 33) config = intent.getSerializableExtra("config", ScanConfig.class);
        else config = (ScanConfig) intent.getSerializableExtra("config");
        if (config == null) { stopSelf(); return START_NOT_STICKY; }
        engine = new ScanEngine(new NvdClient(getCacheDir()),takeCredentials());
        state.running = true; state.completed = 0; state.total = config.ports.size();
        state.message = "Starting scan"; state.report = null; state.persistenceError = "";
        Notification notification = notification();
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        else startForeground(1, notification);
        wakeLock = getSystemService(PowerManager.class).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "ApplePen:scan");
        wakeLock.acquire(config.budgetMs + 60000);
        String network = networkViewpoint();
        worker.execute(() -> {
            ReportStore store = new ReportStore(this);
            // Recover runs interrupted by process death. Completed reports are left untouched.
            for (ScanReport previous : store.list()) if (previous.status.equals("Running")) {
                previous.status = "Interrupted"; previous.finishedAt = System.currentTimeMillis();
                previous.coverage.add("The application process ended before this scan completed; no complete assessment is available.");
                try { store.save(previous); } catch (Exception ignored) { }
            }
            ScanReport report = new ScanReport(config); report.network = network;
            try { store.save(report); } catch (Exception e) { state.persistenceError = "Could not save history: " + e.getMessage(); }
            try {
                report = engine.run(report, (completed, total, message) -> {
                    state.completed = completed; state.total = total; state.message = message;
                    if (System.currentTimeMillis() - lastNotification > 1000) {
                        try { notifications.notify(1, notification()); } catch (SecurityException ignored) { }
                        lastNotification = System.currentTimeMillis();
                    }
                });
            } catch (Exception e) { report.status = "Failed"; report.error = String.valueOf(e.getMessage()); report.finishedAt = System.currentTimeMillis(); }
            try { store.save(report); } catch (Exception e) { state.persistenceError = "Could not save history: " + e.getMessage(); }
            state.report = report; state.message = report.summary(); state.running = false;
            if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
            stopForeground(STOP_FOREGROUND_REMOVE); stopSelf();
        });
        return START_NOT_STICKY;
    }
    private Notification notification() {
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        PendingIntent cancel = PendingIntent.getService(this, 1, new Intent(this, ScanService.class).setAction(CANCEL), PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this, "scan").setSmallIcon(R.drawable.ic_launcher)
            .setContentTitle("ApplePen · security assessment").setContentText(state.message)
            .setProgress(Math.max(1, state.total), state.completed, state.completed == state.total)
            .setContentIntent(open).setOngoing(true).setOnlyAlertOnce(true)
            .addAction(new Notification.Action.Builder(null, "Stop", cancel).build()).build();
    }
    private String networkViewpoint() {
        try {
            ConnectivityManager cm = getSystemService(ConnectivityManager.class);
            NetworkCapabilities caps = cm.getNetworkCapabilities(cm.getActiveNetwork());
            if (caps == null) return "Phone · no active network reported";
            StringBuilder b = new StringBuilder("Phone · ");
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) b.append("VPN ");
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) b.append("Wi-Fi ");
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) b.append("mobile data ");
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) b.append("Ethernet ");
            return b.append("· active Android routing at scan start").toString();
        } catch (Exception e) { return "Phone · network unavailable"; }
    }
    @Override public void onTimeout(int startId, int fgsType) { if (engine != null) engine.cancel(); stopSelf(); }
    @Override public void onDestroy() { if (engine != null && state.running) engine.cancel(); if (wakeLock != null && wakeLock.isHeld()) wakeLock.release(); worker.shutdown(); super.onDestroy(); }
    @Override public IBinder onBind(Intent intent) { return null; }
}

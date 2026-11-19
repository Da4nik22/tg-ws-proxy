package dev.personal.tgws;

import android.Manifest;
import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Insets;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.provider.Settings;
import android.view.View;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import dev.personal.tgws.core.ProxyServer;

public class MainActivity extends Activity {

    private final Handler ui = new Handler(Looper.getMainLooper());

    private ProxyConfig cfg;
    private TextView tvStatus;
    private TextView tvDetail;
    private TextView tvLink;
    private TextView tvStats;
    private TextView tvLog;
    private Button btnToggle;
    private EditText etPort;
    private EditText etDc;
    private EditText etPool;
    private CheckBox cbVerbose;
    private CheckBox cbBoot;
    private CheckBox cbOpen;
    private TextView tvBattery;
    private String lastLog = "";

    private final Runnable tick = new Runnable() {
        @Override
        public void run() {
            refresh();
            ui.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LogBuffer.install();
        cfg = new ProxyConfig(this);
        setContentView(R.layout.activity_main);

        // Android 15+/16 draw edge to edge: keep content clear of the system bars and the keyboard.
        View root = findViewById(R.id.scroll);
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            Insets bars = insets.getInsets(
                WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout() | WindowInsets.Type.ime());
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return WindowInsets.CONSUMED;
        });

        tvStatus = findViewById(R.id.tvStatus);
        tvDetail = findViewById(R.id.tvDetail);
        tvLink = findViewById(R.id.tvLink);
        tvStats = findViewById(R.id.tvStats);
        tvLog = findViewById(R.id.tvLog);
        btnToggle = findViewById(R.id.btnToggle);
        etPort = findViewById(R.id.etPort);
        etDc = findViewById(R.id.etDc);
        etPool = findViewById(R.id.etPool);
        cbVerbose = findViewById(R.id.cbVerbose);
        cbBoot = findViewById(R.id.cbBoot);
        cbOpen = findViewById(R.id.cbOpen);
        tvBattery = findViewById(R.id.tvBattery);

        etPort.setText(String.valueOf(cfg.port()));
        etDc.setText(cfg.dcIps());
        etPool.setText(String.valueOf(cfg.pool()));
        cbVerbose.setChecked(cfg.verbose());

        // Autostart options apply at once: they need no restart of the proxy.
        cbBoot.setChecked(cfg.autostartBoot());
        cbOpen.setChecked(cfg.autostartOpen());
        cbBoot.setOnCheckedChangeListener((b, checked) -> cfg.setAutostartBoot(checked));
        cbOpen.setOnCheckedChangeListener((b, checked) -> cfg.setAutostartOpen(checked));

        btnToggle.setOnClickListener(v -> {
            ProxyRuntime.Status st = ProxyRuntime.status();
            if (st == ProxyRuntime.Status.RUNNING || st == ProxyRuntime.Status.STARTING) {
                ProxyService.stop(this);
            } else {
                ProxyService.start(this);
            }
        });
        findViewById(R.id.btnOpen).setOnClickListener(v -> openInTelegram());
        findViewById(R.id.btnCopy).setOnClickListener(v -> copyLink());
        findViewById(R.id.btnSave).setOnClickListener(v -> saveSettings());
        findViewById(R.id.btnBattery).setOnClickListener(v ->
            startActivity(new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)));

        if (Build.VERSION.SDK_INT >= 33
            && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1);
        }

        // Fresh launch only: a rotation or theme change recreates the activity and must not restart anything.
        if (savedInstanceState == null && cfg.autostartOpen()
            && ProxyRuntime.status() == ProxyRuntime.Status.STOPPED) {
            ProxyService.start(this);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        ui.post(tick);
    }

    @Override
    protected void onPause() {
        ui.removeCallbacks(tick);
        super.onPause();
    }

    private void refresh() {
        ProxyRuntime.Status st = ProxyRuntime.status();
        switch (st) {
            case RUNNING:
                tvStatus.setText(R.string.status_running);
                tvDetail.setText(getString(R.string.listening_on, ProxyRuntime.detail()));
                break;
            case STARTING:
                tvStatus.setText(R.string.status_starting);
                tvDetail.setText("");
                break;
            case FAILED:
                tvStatus.setText(R.string.status_failed);
                tvDetail.setText(ProxyRuntime.detail());
                break;
            default:
                tvStatus.setText(R.string.status_stopped);
                tvDetail.setText("");
                break;
        }
        boolean active = st == ProxyRuntime.Status.RUNNING || st == ProxyRuntime.Status.STARTING;
        btnToggle.setText(active ? R.string.btn_stop : R.string.btn_start);

        tvLink.setText(cfg.link());

        PowerManager pm = getSystemService(PowerManager.class);
        boolean unrestricted = pm != null && pm.isIgnoringBatteryOptimizations(getPackageName());
        tvBattery.setText(unrestricted ? R.string.battery_ok : R.string.battery_restricted);

        ProxyServer server = ProxyRuntime.server();
        tvStats.setText(server != null ? server.stats().summary() : "-");

        String log = LogBuffer.snapshot();
        if (!log.equals(lastLog)) {
            lastLog = log;
            tvLog.setText(log);
        }
    }

    private void openInTelegram() {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(cfg.link())));
        } catch (ActivityNotFoundException e) {
            Toast.makeText(this, R.string.toast_no_telegram, Toast.LENGTH_LONG).show();
        }
    }

    private void copyLink() {
        ClipboardManager cm = getSystemService(ClipboardManager.class);
        cm.setPrimaryClip(ClipData.newPlainText("tg proxy", cfg.link()));
        Toast.makeText(this, R.string.toast_copied, Toast.LENGTH_SHORT).show();
    }

    private void saveSettings() {
        int port;
        int pool;
        try {
            port = Integer.parseInt(etPort.getText().toString().trim());
            if (port < 1024 || port > 65535) {
                throw new NumberFormatException();
            }
        } catch (NumberFormatException e) {
            Toast.makeText(this, R.string.err_port, Toast.LENGTH_LONG).show();
            return;
        }
        try {
            pool = Integer.parseInt(etPool.getText().toString().trim());
            if (pool < 0 || pool > 16) {
                throw new NumberFormatException();
            }
        } catch (NumberFormatException e) {
            Toast.makeText(this, R.string.err_pool, Toast.LENGTH_LONG).show();
            return;
        }
        String dcIps = etDc.getText().toString().trim();
        try {
            ProxyConfig.parseDcIps(dcIps);
        } catch (IllegalArgumentException e) {
            Toast.makeText(this, getString(R.string.err_dc, e.getMessage()), Toast.LENGTH_LONG).show();
            return;
        }

        cfg.save(port, dcIps, pool, cbVerbose.isChecked());
        ProxyRuntime.Status st = ProxyRuntime.status();
        if (st == ProxyRuntime.Status.RUNNING || st == ProxyRuntime.Status.STARTING) {
            ProxyService.restart(this);
        }
        Toast.makeText(this, R.string.toast_saved, Toast.LENGTH_SHORT).show();
        refresh();
    }
}

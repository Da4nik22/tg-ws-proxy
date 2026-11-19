package dev.personal.tgws;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/**
 * Starts the proxy after the phone boots or after the app is updated (an update kills the
 * running process), when the user turned autostart on.
 */
public class BootReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = (intent != null) ? intent.getAction() : null;
        if (!Intent.ACTION_BOOT_COMPLETED.equals(action)
            && !Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)) {
            return;
        }
        LogBuffer.install();
        if (!new ProxyConfig(context).autostartBoot()) {
            return;
        }
        LogBuffer.add("I Autostart (" + action + ")");
        try {
            ProxyService.start(context);
        } catch (RuntimeException e) {
            // e.g. ForegroundServiceStartNotAllowedException when the system refuses the start
            LogBuffer.add("E Autostart failed: " + e);
        }
    }
}

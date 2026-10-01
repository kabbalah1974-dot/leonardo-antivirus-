package it.leonardo.antivirus;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings;
import android.view.accessibility.AccessibilityManager;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Guarda le app installate dall'utente (non quelle di sistema) e dà un punteggio di rischio
 * in base a da dove arrivano e a cosa possono fare. Non legge dentro le app: Android non lo permette.
 */
public final class AppScanner {

    public static final class Result {
        public final int totalUserApps;
        public final List<AppInfo> apps;

        Result(int totalUserApps, List<AppInfo> apps) {
            this.totalUserApps = totalUserApps;
            this.apps = apps;
        }
    }

    private static final Set<String> STORES = new HashSet<>(Arrays.asList(
            "com.android.vending",
            "com.sec.android.app.samsungapps",
            "com.amazon.venezia",
            "com.huawei.appmarket",
            "com.xiaomi.mipicks",
            "org.fdroid.fdroid",
            "org.fdroid.basic"));

    private final Context context;

    public AppScanner(Context context) {
        this.context = context.getApplicationContext();
    }

    public Result scan() {
        PackageManager pm = context.getPackageManager();
        Set<String> accessibility = enabledAccessibilityPackages();
        Set<String> admins = adminPackages();
        Set<String> listeners = notificationListenerPackages();

        List<AppInfo> apps = new ArrayList<>();
        int total = 0;
        for (PackageInfo p : installedPackages(pm)) {
            ApplicationInfo ai = p.applicationInfo;
            if (ai == null) continue;
            if ((ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0) continue;
            if (p.packageName.equals(context.getPackageName())) continue;
            total++;

            Set<String> permissions = new HashSet<>();
            if (p.requestedPermissions != null) permissions.addAll(Arrays.asList(p.requestedPermissions));
            String installer = installerOf(pm, p.packageName);
            boolean fromStore = installer != null && STORES.contains(installer);

            int score = 0;
            List<String> reasons = new ArrayList<>();

            if (!fromStore) {
                score += 1;
                reasons.add("Non è stata installata da un negozio affidabile.");
            }
            if (accessibility.contains(p.packageName)) {
                score += fromStore ? 3 : 5;
                reasons.add("Ha il controllo dello schermo attivo (accessibilità): può leggere e toccare al posto tuo.");
            }
            if (admins.contains(p.packageName)) {
                score += fromStore ? 2 : 3;
                reasons.add("È amministratore del dispositivo e può essere difficile da disinstallare.");
            }
            if (listeners.contains(p.packageName)) {
                score += fromStore ? 1 : 3;
                reasons.add("Legge le tue notifiche, compresi i codici di verifica.");
            }
            boolean readsSms = permissions.contains("android.permission.READ_SMS")
                    || permissions.contains("android.permission.RECEIVE_SMS");
            boolean overlay = permissions.contains("android.permission.SYSTEM_ALERT_WINDOW");
            if (readsSms) {
                score += fromStore ? 1 : 2;
                reasons.add("Può leggere i tuoi SMS.");
            }
            if (overlay && readsSms) {
                score += 3;
                reasons.add("Può disegnare sopra le altre app e leggere gli SMS: è la combinazione tipica dei virus che rubano i dati della banca.");
            } else if (overlay && !fromStore) {
                score += 1;
                reasons.add("Può disegnare sopra le altre app.");
            }
            if (!fromStore && permissions.contains("android.permission.REQUEST_INSTALL_PACKAGES")) {
                score += 1;
                reasons.add("Può installare altre app.");
            }
            if ((ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                score += 1;
                reasons.add("È una versione di prova (debug), non una app normale.");
            }

            apps.add(new AppInfo(
                    p.packageName,
                    String.valueOf(pm.getApplicationLabel(ai)),
                    ai.sourceDir == null ? "" : ai.sourceDir,
                    fromStore,
                    score,
                    reasons));
        }
        Collections.sort(apps, (a, b) -> Integer.compare(b.score, a.score));
        return new Result(total, apps);
    }

    @SuppressWarnings("deprecation")
    private List<PackageInfo> installedPackages(PackageManager pm) {
        if (Build.VERSION.SDK_INT >= 33) {
            return pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS));
        }
        return pm.getInstalledPackages(PackageManager.GET_PERMISSIONS);
    }

    @SuppressWarnings("deprecation")
    private String installerOf(PackageManager pm, String packageName) {
        try {
            if (Build.VERSION.SDK_INT >= 30) {
                return pm.getInstallSourceInfo(packageName).getInstallingPackageName();
            }
            return pm.getInstallerPackageName(packageName);
        } catch (Exception e) {
            return null;
        }
    }

    private Set<String> enabledAccessibilityPackages() {
        Set<String> out = new HashSet<>();
        AccessibilityManager am = (AccessibilityManager) context.getSystemService(Context.ACCESSIBILITY_SERVICE);
        if (am == null) return out;
        for (AccessibilityServiceInfo info : am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)) {
            if (info.getResolveInfo() != null && info.getResolveInfo().serviceInfo != null) {
                out.add(info.getResolveInfo().serviceInfo.packageName);
            }
        }
        return out;
    }

    private Set<String> adminPackages() {
        Set<String> out = new HashSet<>();
        DevicePolicyManager dpm = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
        if (dpm == null) return out;
        List<ComponentName> admins = dpm.getActiveAdmins();
        if (admins != null) {
            for (ComponentName cn : admins) out.add(cn.getPackageName());
        }
        return out;
    }

    private Set<String> notificationListenerPackages() {
        Set<String> out = new HashSet<>();
        String flat = Settings.Secure.getString(context.getContentResolver(), "enabled_notification_listeners");
        if (flat == null || flat.isEmpty()) return out;
        for (String part : flat.split(":")) {
            ComponentName cn = ComponentName.unflattenFromString(part);
            if (cn != null) out.add(cn.getPackageName());
        }
        return out;
    }
}

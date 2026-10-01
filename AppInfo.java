package it.leonardo.antivirus;

import java.util.List;

/** Un'app installata, con il punteggio di rischio calcolato da AppScanner. */
public final class AppInfo {
    public final String packageName;
    public final String label;
    public final String apkPath;
    public final boolean fromStore;
    public final int score;
    public final List<String> reasons;

    public AppInfo(String packageName, String label, String apkPath, boolean fromStore, int score, List<String> reasons) {
        this.packageName = packageName;
        this.label = label;
        this.apkPath = apkPath;
        this.fromStore = fromStore;
        this.score = score;
        this.reasons = reasons;
    }
}

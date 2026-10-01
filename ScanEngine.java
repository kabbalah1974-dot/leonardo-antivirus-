package it.leonardo.antivirus;

import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.provider.OpenableColumns;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Coordina i controlli: lavora su un thread in background e consegna all'interfaccia
 * una fotografia (UiState) a ogni passo.
 */
public final class ScanEngine {

    public interface Listener {
        /** Chiamato sempre sul thread principale. */
        void onState(UiState state);
    }

    private interface Task {
        void run() throws Exception;
    }

    private interface Mod {
        void apply(UiState state);
    }

    /** Il piano gratuito di VirusTotal permette 4 richieste al minuto: una ogni 16 secondi è sicuro. */
    private static final long PAUSE_MS = 16_000L;
    private static final long RATE_LIMIT_WAIT_MS = 60_000L;
    private static final int MAX_ONLINE_APPS = 15;
    private static final int MAX_FILES = 20;

    private final Context context;
    private final Listener listener;
    private final KeyVault vault;
    private final VirusTotalClient vt = new VirusTotalClient();
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private Future<?> task;
    private UiState state = new UiState();

    public ScanEngine(Context context, Listener listener) {
        this.context = context.getApplicationContext();
        this.listener = listener;
        this.vault = new KeyVault(this.context);
        state.hasKey = vault.load() != null;
    }

    // ---------- comandi dall'interfaccia ----------

    /** Rimanda all'interfaccia lo stato attuale (da chiamare quando la schermata è pronta). */
    public void refresh() {
        change(s -> { });
    }

    public synchronized boolean hasKey() {
        return state.hasKey;
    }

    public void saveKey(String key) {
        try {
            vault.save(key);
            final boolean has = vault.load() != null;
            change(s -> s.hasKey = has);
        } catch (Exception e) {
            change(s -> s.status = "Non sono riuscito a salvare la chiave.");
        }
    }

    public synchronized void scanApps() {
        if (state.busy) return;
        change(s -> {
            s.busy = true;
            s.appsDone = false;
            s.appFindings = Collections.emptyList();
            s.status = "Controllo le app installate…";
        });
        start(this::runAppScan);
    }

    public synchronized void scanFiles(List<Uri> uris) {
        if (state.busy || uris.isEmpty()) return;
        final List<Uri> copy = new ArrayList<>(uris);
        change(s -> {
            s.busy = true;
            s.fileFindings = Collections.emptyList();
            s.status = "Leggo i file…";
        });
        start(() -> runFileScan(copy));
    }

    public synchronized void cancel() {
        if (task != null) task.cancel(true);
        change(s -> {
            s.busy = false;
            s.status = "Controllo interrotto.";
        });
    }

    public void shutdown() {
        executor.shutdownNow();
    }

    // ---------- controllo delle app ----------

    private void runAppScan() throws Exception {
        final AppScanner.Result result = new AppScanner(context).scan();
        checkCancel();

        List<Finding> findings = new ArrayList<>();
        for (AppInfo a : result.apps) {
            if (a.score > 0) findings.add(toFinding(a));
        }
        final List<Finding> first = sorted(findings);
        change(s -> {
            s.appsChecked = result.totalUserApps;
            s.appFindings = first;
        });

        String key = vault.load();
        final List<AppInfo> candidates = new ArrayList<>();
        for (AppInfo a : result.apps) {
            if (!a.fromStore && candidates.size() < MAX_ONLINE_APPS) candidates.add(a);
        }
        if (key == null || candidates.isEmpty()) {
            final String msg = key == null
                    ? "Controllo finito. Per il controllo online aggiungi la chiave VirusTotal nelle Impostazioni."
                    : "Controllo finito.";
            change(s -> {
                s.busy = false;
                s.appsDone = true;
                s.status = msg;
            });
            return;
        }

        for (int i = 0; i < candidates.size(); i++) {
            final AppInfo app = candidates.get(i);
            if (i > 0) Thread.sleep(PAUSE_MS);
            final String progress = "Controllo online " + (i + 1) + " di " + candidates.size() + ": " + app.label;
            change(s -> s.status = progress);

            String hash = hashFile(app.apkPath);
            if (hash == null) continue;
            final VtResult r = lookup(hash, key);
            checkCancel();
            if (r.kind == VtResult.Kind.BAD_KEY) {
                stopBadKey();
                return;
            }
            change(s -> {
                List<Finding> updated = new ArrayList<>();
                for (Finding f : s.appFindings) {
                    updated.add(f.id.equals(app.packageName) ? appWithVt(f, r) : f);
                }
                s.appFindings = sorted(updated);
            });
        }
        change(s -> {
            s.busy = false;
            s.appsDone = true;
            s.status = "Controllo finito.";
        });
    }

    private static Finding toFinding(AppInfo a) {
        Severity severity;
        if (a.score >= 6) severity = Severity.HIGH;
        else if (a.score >= 3) severity = Severity.MEDIUM;
        else severity = Severity.LOW;
        return new Finding(a.packageName, a.label, a.packageName, severity, a.reasons);
    }

    private static Finding appWithVt(Finding f, VtResult r) {
        switch (r.kind) {
            case FOUND: {
                Severity vtSeverity = severityFor(r);
                Severity result = vtSeverity.ordinal() < f.severity.ordinal() ? vtSeverity : f.severity;
                return f.with(result, vtLine(r));
            }
            case NOT_FOUND:
                return f.with(f.severity, "VirusTotal non conosce questa app: non è mai stata analizzata.");
            case FAILED:
                return f.with(f.severity, "Controllo online non riuscito: " + r.message + ".");
            default:
                return f;
        }
    }

    // ---------- controllo dei file scelti dall'utente ----------

    private void runFileScan(List<Uri> all) throws Exception {
        List<Uri> uris = all.size() > MAX_FILES ? all.subList(0, MAX_FILES) : all;
        String key = vault.load();
        int lookups = 0;

        for (int i = 0; i < uris.size(); i++) {
            Uri uri = uris.get(i);
            final String name = displayName(uri);
            final String progress = "File " + (i + 1) + " di " + uris.size() + ": " + name;
            change(s -> s.status = progress);
            String id = "f" + i + "-" + name;

            String hash = hashUri(uri);
            checkCancel();
            if (hash == null) {
                addFile(new Finding(id, name, "", Severity.UNKNOWN,
                        Collections.singletonList("Non sono riuscito a leggere questo file.")));
                continue;
            }

            List<String> base = new ArrayList<>();
            if (name.toLowerCase(Locale.ROOT).endsWith(".apk")) {
                base.add("È un'app installabile (APK). Installala solo se sai da dove viene.");
            }
            base.add("Impronta SHA-256: " + hash.substring(0, 16) + "…");

            if (key == null) {
                List<String> reasons = new ArrayList<>();
                reasons.add("Aggiungi la chiave VirusTotal nelle Impostazioni per il controllo online.");
                reasons.addAll(base);
                addFile(new Finding(id, name, "", Severity.UNKNOWN, reasons));
                continue;
            }

            if (lookups > 0) Thread.sleep(PAUSE_MS);
            lookups++;
            VtResult r = lookup(hash, key);
            checkCancel();

            List<String> reasons = new ArrayList<>();
            Severity severity = Severity.UNKNOWN;
            switch (r.kind) {
                case FOUND:
                    severity = severityFor(r);
                    reasons.add(vtLine(r));
                    break;
                case NOT_FOUND:
                    reasons.add("VirusTotal non conosce questo file. Non vuol dire che sia sicuro: nessuno l'ha mai analizzato.");
                    break;
                case BAD_KEY:
                    stopBadKey();
                    return;
                case RATE_LIMITED:
                    reasons.add("VirusTotal ha chiesto una pausa. Riprova tra un minuto.");
                    break;
                default:
                    reasons.add("Controllo online non riuscito: " + r.message + ".");
                    break;
            }
            reasons.addAll(base);
            addFile(new Finding(id, name, "", severity, reasons));
        }

        final String extra = all.size() > MAX_FILES
                ? " Controllati i primi " + MAX_FILES + " file su " + all.size() + "."
                : "";
        change(s -> {
            s.busy = false;
            s.fileFindings = sorted(s.fileFindings);
            s.status = "Controllo finito." + extra;
        });
    }

    private void addFile(final Finding f) {
        change(s -> {
            List<Finding> next = new ArrayList<>(s.fileFindings);
            next.add(f);
            s.fileFindings = next;
        });
    }

    private String displayName(Uri uri) {
        try (Cursor c = context.getContentResolver().query(
                uri, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                String name = c.getString(0);
                if (name != null) return name;
            }
        } catch (Exception ignored) {
            // si usa il nome di riserva qui sotto
        }
        String last = uri.getLastPathSegment();
        return last != null ? last : "file";
    }

    private String hashUri(Uri uri) {
        try (InputStream in = context.getContentResolver().openInputStream(uri)) {
            return in == null ? null : sha256(in);
        } catch (Exception e) {
            return null;
        }
    }

    private String hashFile(String path) {
        if (path == null || path.isEmpty()) return null;
        try (InputStream in = new FileInputStream(new File(path))) {
            return sha256(in);
        } catch (Exception e) {
            return null;
        }
    }

    // ---------- parti in comune ----------

    private void start(Task t) {
        task = executor.submit(() -> {
            try {
                t.run();
            } catch (InterruptedException e) {
                // interrotto dall'utente: cancel() ha già aggiornato lo stato
            } catch (Exception e) {
                fail(e);
            }
        });
    }

    private void checkCancel() throws InterruptedException {
        if (Thread.currentThread().isInterrupted()) throw new InterruptedException();
    }

    private VtResult lookup(String hash, String key) throws InterruptedException {
        VtResult r = vt.lookup(hash, key);
        if (r.kind == VtResult.Kind.RATE_LIMITED) {
            change(s -> s.status = "VirusTotal chiede una pausa. Aspetto un minuto…");
            Thread.sleep(RATE_LIMIT_WAIT_MS);
            r = vt.lookup(hash, key);
        }
        return r;
    }

    private void stopBadKey() {
        change(s -> {
            s.busy = false;
            s.status = "La chiave VirusTotal non è valida. Controllala nelle Impostazioni.";
        });
    }

    private void fail(final Exception e) {
        final String why = e.getMessage() != null ? e.getMessage() : "errore sconosciuto";
        change(s -> {
            s.busy = false;
            s.status = "Qualcosa è andato storto: " + why + ".";
        });
    }

    private synchronized void change(Mod mod) {
        UiState next = new UiState(state);
        mod.apply(next);
        state = next;
        final UiState snapshot = next;
        main.post(() -> listener.onState(snapshot));
    }

    private static List<Finding> sorted(List<Finding> list) {
        List<Finding> copy = new ArrayList<>(list);
        Collections.sort(copy, (a, b) -> {
            int bySeverity = Integer.compare(a.severity.ordinal(), b.severity.ordinal());
            if (bySeverity != 0) return bySeverity;
            return a.title.toLowerCase(Locale.ROOT).compareTo(b.title.toLowerCase(Locale.ROOT));
        });
        return copy;
    }

    private static Severity severityFor(VtResult r) {
        if (r.malicious >= 3) return Severity.HIGH;
        if (r.malicious >= 1) return Severity.MEDIUM;
        if (r.suspicious >= 1) return Severity.LOW;
        return Severity.OK;
    }

    private static String vtLine(VtResult r) {
        if (r.malicious + r.suspicious == 0) {
            return "VirusTotal: nessuno dei " + r.total + " antivirus lo segnala.";
        }
        return "VirusTotal: " + r.malicious + " antivirus su " + r.total
                + " lo segnalano come pericoloso, " + r.suspicious + " come sospetto.";
    }

    private static String sha256(InputStream in) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[64 * 1024];
        int n;
        while ((n = in.read(buffer)) != -1) md.update(buffer, 0, n);
        StringBuilder sb = new StringBuilder();
        for (byte b : md.digest()) sb.append(String.format(Locale.ROOT, "%02x", b));
        return sb.toString();
    }
}

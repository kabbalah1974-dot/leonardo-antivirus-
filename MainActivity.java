package it.leonardo.antivirus;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.Intent;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.text.InputType;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;

/** Unica schermata: due pulsanti, lo stato del controllo e l'elenco delle segnalazioni. */
public class MainActivity extends Activity implements ScanEngine.Listener {

    private static final int REQ_PICK_FILES = 42;
    private static final int MAX_WIDTH_DP = 700;

    private ScanEngine engine;
    private LinearLayout column;
    private Button buttonApps;
    private Button buttonFiles;
    private Button buttonStop;
    private TextView statusText;
    private TextView summaryText;
    private LinearLayout results;
    private List<Finding> shownApps;
    private List<Finding> shownFiles;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        engine = new ScanEngine(getApplicationContext(), this);
        setContentView(buildUi());
        applyColumnWidth();
        engine.refresh();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        engine.shutdown();
    }

    @Override
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        applyColumnWidth();
    }

    // ---------- costruzione della schermata ----------

    private View buildUi() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);

        column = new LinearLayout(this);
        column.setOrientation(LinearLayout.VERTICAL);
        column.setPadding(dp(16), dp(24), dp(16), dp(32));
        scroll.addView(column, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT, Gravity.CENTER_HORIZONTAL));

        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout titles = new LinearLayout(this);
        titles.setOrientation(LinearLayout.VERTICAL);
        titles.addView(text("Leonardo Antivirus", 26, true));
        titles.addView(text("Controlla app e file sospetti", 14, false));
        header.addView(titles, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        Button settings = new Button(this);
        settings.setText("Impostazioni");
        settings.setOnClickListener(v -> showKeyDialog());
        header.addView(settings);
        column.addView(header);

        LinearLayout actions = new LinearLayout(this);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        buttonApps = new Button(this);
        buttonApps.setText("Controlla le app");
        buttonApps.setOnClickListener(v -> engine.scanApps());
        buttonFiles = new Button(this);
        buttonFiles.setText("Controlla file");
        buttonFiles.setOnClickListener(v -> pickFiles());
        actions.addView(buttonApps, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        actions.addView(buttonFiles, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        column.addView(actions, topMargin(16));

        LinearLayout statusBox = new LinearLayout(this);
        statusBox.setOrientation(LinearLayout.VERTICAL);
        statusBox.setPadding(dp(14), dp(14), dp(14), dp(14));
        statusBox.setBackground(outline(0x66888888, 0));
        statusText = text("", 16, false);
        summaryText = text("", 14, false);
        summaryText.setVisibility(View.GONE);
        buttonStop = new Button(this);
        buttonStop.setText("Interrompi");
        buttonStop.setVisibility(View.GONE);
        buttonStop.setOnClickListener(v -> engine.cancel());
        statusBox.addView(statusText);
        statusBox.addView(summaryText, topMargin(6));
        statusBox.addView(buttonStop, topMargin(6));
        column.addView(statusBox, topMargin(12));

        results = new LinearLayout(this);
        results.setOrientation(LinearLayout.VERTICAL);
        column.addView(results, topMargin(4));

        LinearLayout info = new LinearLayout(this);
        info.setOrientation(LinearLayout.VERTICAL);
        info.setPadding(dp(14), dp(14), dp(14), dp(14));
        info.setBackground(outline(0x66888888, 0));
        info.addView(text("Cosa può e non può fare", 17, true));
        info.addView(text("Android non permette a un'app di guardare dentro le altre. Questo controllo guarda da dove "
                + "arrivano le app, che permessi hanno e, con la chiave VirusTotal, se i loro file sono già noti come pericolosi.",
                14, false), topMargin(6));
        info.addView(text("Un risultato pulito riduce il dubbio ma non è una garanzia: un virus nuovo, mai analizzato, "
                + "non viene riconosciuto. Online va solo l'impronta del file, mai il file.", 14, false), topMargin(6));
        column.addView(info, topMargin(20));

        return scroll;
    }

    private void applyColumnWidth() {
        int screen = getResources().getDisplayMetrics().widthPixels;
        int width = Math.min(screen, dp(MAX_WIDTH_DP));
        FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(
                width, FrameLayout.LayoutParams.WRAP_CONTENT, Gravity.CENTER_HORIZONTAL);
        column.setLayoutParams(lp);
    }

    // ---------- aggiornamento dallo stato ----------

    @Override
    public void onState(UiState s) {
        statusText.setText(s.status);
        buttonApps.setEnabled(!s.busy);
        buttonFiles.setEnabled(!s.busy);
        buttonStop.setVisibility(s.busy ? View.VISIBLE : View.GONE);

        if (s.appsDone) {
            int high = 0;
            int medium = 0;
            int low = 0;
            for (Finding f : s.appFindings) {
                if (f.severity == Severity.HIGH) high++;
                else if (f.severity == Severity.MEDIUM) medium++;
                else if (f.severity == Severity.LOW) low++;
            }
            summaryText.setText("Controllate " + s.appsChecked + " app. Rischio alto: " + high
                    + " · medio: " + medium + " · basso: " + low);
            summaryText.setVisibility(View.VISIBLE);
        } else {
            summaryText.setVisibility(View.GONE);
        }

        if (s.appFindings != shownApps || s.fileFindings != shownFiles) {
            shownApps = s.appFindings;
            shownFiles = s.fileFindings;
            renderResults(s);
        }
    }

    private void renderResults(UiState s) {
        results.removeAllViews();
        if (!s.appFindings.isEmpty()) {
            results.addView(sectionTitle("App da guardare"));
            for (Finding f : s.appFindings) results.addView(card(f), topMargin(8));
        } else if (s.appsDone) {
            results.addView(text("Nessuna app da segnalare.", 16, false), topMargin(12));
        }
        if (!s.fileFindings.isEmpty()) {
            results.addView(sectionTitle("File controllati"));
            for (Finding f : s.fileFindings) results.addView(card(f), topMargin(8));
        }
    }

    private View sectionTitle(String title) {
        TextView t = text(title, 20, true);
        t.setPadding(0, dp(16), 0, 0);
        return t;
    }

    private View card(Finding f) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(14), dp(14), dp(14), dp(14));
        card.setBackground(outline(0x66888888, 0));

        LinearLayout top = new LinearLayout(this);
        top.setOrientation(LinearLayout.HORIZONTAL);
        top.setGravity(Gravity.CENTER_VERTICAL);
        top.addView(badge(f.severity));
        TextView title = text(f.title, 17, true);
        title.setPadding(dp(10), 0, 0, 0);
        top.addView(title, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        card.addView(top);

        if (!f.subtitle.isEmpty()) card.addView(text(f.subtitle, 12, false), topMargin(4));
        for (String reason : f.reasons) card.addView(text("• " + reason, 14, false), topMargin(6));
        return card;
    }

    private View badge(Severity severity) {
        int color;
        switch (severity) {
            case HIGH: color = 0xFFB3261E; break;
            case MEDIUM: color = 0xFFA85400; break;
            case LOW: color = 0xFF7A6A00; break;
            case UNKNOWN: color = 0xFF5F6368; break;
            default: color = 0xFF1B6E3E; break;
        }
        TextView t = text(severity.label, 12, true);
        t.setTextColor(Color.WHITE);
        t.setPadding(dp(10), dp(3), dp(10), dp(3));
        t.setBackground(outline(color, color));
        return t;
    }

    // ---------- chiave VirusTotal e scelta dei file ----------

    private void showKeyDialog() {
        final EditText input = new EditText(this);
        input.setHint("API key");
        input.setSingleLine(true);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        FrameLayout holder = new FrameLayout(this);
        holder.setPadding(dp(20), dp(8), dp(20), 0);
        holder.addView(input);

        String message = "Serve per il controllo online. Crea un account gratuito su virustotal.com, "
                + "apri il tuo profilo e copia la API key qui sotto. Resta cifrata sul dispositivo.";
        if (engine.hasKey()) message += "\n\nUna chiave è già salvata. Incollane una nuova per sostituirla.";

        AlertDialog.Builder builder = new AlertDialog.Builder(this)
                .setTitle("Chiave VirusTotal")
                .setMessage(message)
                .setView(holder)
                .setPositiveButton("Salva", (d, w) -> {
                    String key = input.getText().toString().trim();
                    if (!key.isEmpty()) engine.saveKey(key);
                })
                .setNegativeButton("Annulla", null);
        if (engine.hasKey()) builder.setNeutralButton("Rimuovi", (d, w) -> engine.saveKey(""));
        builder.show();
    }

    private void pickFiles() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
        startActivityForResult(intent, REQ_PICK_FILES);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQ_PICK_FILES || resultCode != RESULT_OK || data == null) return;
        List<Uri> uris = new ArrayList<>();
        ClipData clip = data.getClipData();
        if (clip != null) {
            for (int i = 0; i < clip.getItemCount(); i++) uris.add(clip.getItemAt(i).getUri());
        } else if (data.getData() != null) {
            uris.add(data.getData());
        }
        engine.scanFiles(uris);
    }

    // ---------- piccoli aiuti per costruire le viste ----------

    private TextView text(String value, int sp, boolean bold) {
        TextView t = new TextView(this);
        t.setText(value);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    private GradientDrawable outline(int strokeColor, int fillColor) {
        GradientDrawable d = new GradientDrawable();
        d.setCornerRadius(dp(fillColor == 0 ? 12 : 20));
        if (fillColor != 0) d.setColor(fillColor);
        else d.setStroke(dp(1), strokeColor);
        return d;
    }

    private LinearLayout.LayoutParams topMargin(int dp) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(dp);
        return lp;
    }

    private int dp(int value) {
        return Math.round(TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, value, getResources().getDisplayMetrics()));
    }
}

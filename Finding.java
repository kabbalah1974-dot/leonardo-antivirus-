package it.leonardo.antivirus;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Una voce del rapporto: un'app o un file, con i motivi per cui è stata segnalata. */
public final class Finding {
    public final String id;
    public final String title;
    public final String subtitle;
    public final Severity severity;
    public final List<String> reasons;

    public Finding(String id, String title, String subtitle, Severity severity, List<String> reasons) {
        this.id = id;
        this.title = title;
        this.subtitle = subtitle;
        this.severity = severity;
        this.reasons = Collections.unmodifiableList(new ArrayList<>(reasons));
    }

    /** Copia con una gravità diversa e, se c'è, un motivo in più messo in cima. */
    public Finding with(Severity newSeverity, String firstReason) {
        List<String> all = new ArrayList<>();
        if (firstReason != null) all.add(firstReason);
        all.addAll(reasons);
        return new Finding(id, title, subtitle, newSeverity, all);
    }
}

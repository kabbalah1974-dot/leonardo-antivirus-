package it.leonardo.antivirus;

/** Gravità dalla peggiore alla migliore: l'ordine conta, non cambiarlo. */
public enum Severity {
    HIGH("Alto"),
    MEDIUM("Medio"),
    LOW("Basso"),
    UNKNOWN("Sconosciuto"),
    OK("Pulito");

    public final String label;

    Severity(String label) {
        this.label = label;
    }
}

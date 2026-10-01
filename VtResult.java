package it.leonardo.antivirus;

/** Risposta di VirusTotal a "cosa sai di questo file?". */
public final class VtResult {

    public enum Kind { FOUND, NOT_FOUND, BAD_KEY, RATE_LIMITED, FAILED }

    public final Kind kind;
    public final int malicious;
    public final int suspicious;
    public final int total;
    public final String message;

    private VtResult(Kind kind, int malicious, int suspicious, int total, String message) {
        this.kind = kind;
        this.malicious = malicious;
        this.suspicious = suspicious;
        this.total = total;
        this.message = message;
    }

    public static VtResult found(int malicious, int suspicious, int total) {
        return new VtResult(Kind.FOUND, malicious, suspicious, total, "");
    }

    public static VtResult of(Kind kind) {
        return new VtResult(kind, 0, 0, 0, "");
    }

    public static VtResult failed(String message) {
        return new VtResult(Kind.FAILED, 0, 0, 0, message);
    }
}

package it.leonardo.antivirus;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * Chiede a VirusTotal cosa sa di un file, usando solo la sua impronta (SHA-256).
 * Il file non viene mai inviato. Chiamare da un thread in background.
 */
public final class VirusTotalClient {

    public VtResult lookup(String sha256, String apiKey) {
        HttpURLConnection connection = null;
        try {
            URL url = new URL("https://www.virustotal.com/api/v3/files/" + sha256);
            connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(15000);
            connection.setReadTimeout(20000);
            connection.setRequestProperty("x-apikey", apiKey);
            connection.setRequestProperty("accept", "application/json");
            int code = connection.getResponseCode();
            switch (code) {
                case 200:
                    return parse(readAll(connection.getInputStream()));
                case 404:
                    return VtResult.of(VtResult.Kind.NOT_FOUND);
                case 401:
                case 403:
                    return VtResult.of(VtResult.Kind.BAD_KEY);
                case 429:
                    return VtResult.of(VtResult.Kind.RATE_LIMITED);
                default:
                    return VtResult.failed("errore " + code);
            }
        } catch (IOException e) {
            return VtResult.failed("connessione assente o troppo lenta");
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    private static VtResult parse(String body) {
        try {
            JSONObject stats = new JSONObject(body)
                    .getJSONObject("data")
                    .getJSONObject("attributes")
                    .getJSONObject("last_analysis_stats");
            int malicious = stats.optInt("malicious");
            int suspicious = stats.optInt("suspicious");
            int total = malicious + suspicious + stats.optInt("harmless") + stats.optInt("undetected");
            return VtResult.found(malicious, suspicious, total);
        } catch (Exception e) {
            return VtResult.failed("risposta non leggibile");
        }
    }

    private static String readAll(InputStream in) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) sb.append(line);
            return sb.toString();
        }
    }
}

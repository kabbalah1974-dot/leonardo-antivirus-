package it.leonardo.antivirus;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Conserva la chiave di VirusTotal cifrata. La chiave di cifratura sta nell'Android Keystore
 * e non esce mai dal telefono: nelle preferenze c'è solo il testo cifrato.
 */
public final class KeyVault {

    private static final String ALIAS = "leonardo_vt_key";
    private static final String PREF = "vt";
    private static final String TRANSFORM = "AES/GCM/NoPadding";
    private static final int IV_SIZE = 12;

    private final SharedPreferences prefs;

    public KeyVault(Context context) {
        prefs = context.getSharedPreferences("leonardo_antivirus", Context.MODE_PRIVATE);
    }

    private SecretKey secretKey() throws GeneralSecurityException, IOException {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        Key existing = store.getKey(ALIAS, null);
        if (existing instanceof SecretKey) return (SecretKey) existing;
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(
                ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build());
        return generator.generateKey();
    }

    /** Salva la chiave. Una chiave vuota cancella quella salvata. */
    public void save(String apiKey) throws GeneralSecurityException, IOException {
        if (apiKey == null || apiKey.trim().isEmpty()) {
            prefs.edit().remove(PREF).apply();
            return;
        }
        Cipher cipher = Cipher.getInstance(TRANSFORM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey());
        byte[] encrypted = cipher.doFinal(apiKey.trim().getBytes(StandardCharsets.UTF_8));
        byte[] iv = cipher.getIV();
        byte[] packed = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, packed, 0, iv.length);
        System.arraycopy(encrypted, 0, packed, iv.length, encrypted.length);
        prefs.edit().putString(PREF, Base64.encodeToString(packed, Base64.NO_WRAP)).apply();
    }

    /** Restituisce la chiave, oppure null se non c'è o non si riesce a decifrarla. */
    public String load() {
        String raw = prefs.getString(PREF, null);
        if (raw == null) return null;
        try {
            byte[] bytes = Base64.decode(raw, Base64.NO_WRAP);
            byte[] iv = new byte[IV_SIZE];
            byte[] data = new byte[bytes.length - IV_SIZE];
            System.arraycopy(bytes, 0, iv, 0, IV_SIZE);
            System.arraycopy(bytes, IV_SIZE, data, 0, data.length);
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey(), new GCMParameterSpec(128, iv));
            return new String(cipher.doFinal(data), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }
}

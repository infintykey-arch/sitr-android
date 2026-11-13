package com.sitr.vault;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.security.KeyStore;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

final class DeviceSecurity {
    private static final String PREFS = "sitr_device_gate_v2";
    private static final String ALIAS = "sitr_workspace_biometric_wrap_v2";
    private static final String WRAPPED_KEY = "wrapped_workspace_key";
    private static final String WRAP_IV = "workspace_key_iv";
    private static final int KEY_BITS = 256;
    private static final int TAG_BITS = 128;

    private DeviceSecurity() {}

    static boolean isConfigured(Context context) {
        SharedPreferences prefs = prefs(context);
        return prefs.contains(WRAPPED_KEY) && prefs.contains(WRAP_IV);
    }

    static boolean isFingerprintReady(Context context) {
        try {
            FingerprintManager manager = (FingerprintManager) context.getSystemService(Context.FINGERPRINT_SERVICE);
            return manager != null && manager.isHardwareDetected() && manager.hasEnrolledFingerprints();
        } catch (RuntimeException e) {
            return false;
        }
    }

    static Cipher newSetupCipher() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateBiometricKey());
        return cipher;
    }

    static Cipher newUnlockCipher(Context context) throws Exception {
        byte[] iv = Base64.decode(prefs(context).getString(WRAP_IV, ""), Base64.NO_WRAP);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateBiometricKey(), new GCMParameterSpec(TAG_BITS, iv));
            return cipher;
        } finally {
            Arrays.fill(iv, (byte) 0);
        }
    }

    static byte[] unwrapWorkspaceKey(Context context, Cipher authorizedCipher) throws Exception {
        byte[] wrapped = Base64.decode(prefs(context).getString(WRAPPED_KEY, ""), Base64.NO_WRAP);
        try {
            byte[] key = authorizedCipher.doFinal(wrapped);
            if (key.length != 32) {
                Arrays.fill(key, (byte) 0);
                throw new IllegalStateException("Workspace key has an invalid size");
            }
            return key;
        } finally {
            Arrays.fill(wrapped, (byte) 0);
        }
    }

    static void saveWrappedWorkspaceKey(Context context, Cipher authorizedCipher, byte[] rawKey) throws Exception {
        byte[] wrapped = authorizedCipher.doFinal(rawKey);
        byte[] iv = authorizedCipher.getIV();
        try {
            boolean saved = prefs(context).edit()
                    .putString(WRAPPED_KEY, Base64.encodeToString(wrapped, Base64.NO_WRAP))
                    .putString(WRAP_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
                    .commit();
            if (!saved) throw new IllegalStateException("Could not save protected workspace key");
        } finally {
            Arrays.fill(wrapped, (byte) 0);
            Arrays.fill(iv, (byte) 0);
        }
    }

    @SuppressLint("ApplySharedPref")
    static void clear(Context context) {
        prefs(context).edit().clear().commit();
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            if (keyStore.containsAlias(ALIAS)) keyStore.deleteEntry(ALIAS);
        } catch (Exception ignored) { }
    }

    private static SecretKey getOrCreateBiometricKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (keyStore.containsAlias(ALIAS)) return (SecretKey) keyStore.getKey(ALIAS, null);
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        KeyGenParameterSpec.Builder spec = new KeyGenParameterSpec.Builder(ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(KEY_BITS)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(false);
        if (Build.VERSION.SDK_INT >= 30) {
            spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG);
        } else {
            spec.setUserAuthenticationValidityDurationSeconds(-1);
        }
        generator.init(spec.build());
        return generator.generateKey();
    }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }
}

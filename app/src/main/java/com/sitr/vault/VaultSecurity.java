package com.sitr.vault;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;

final class VaultSecurity {
    private static final String PREFS = "sitr_secure_state_v1";
    private static final String ALIAS = "sitr_biometric_wrap_key_v1";
    private static final String HASH = "password_hash";
    private static final String SALT = "password_salt";
    private static final String WRAPPED = "wrapped_vault_key";
    private static final String WRAP_IV = "wrapped_key_iv";
    private static final int ITERATIONS = 210_000;
    private static final int KEY_BITS = 256;
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_IV_BYTES = 12;

    private VaultSecurity() {}

    static boolean isConfigured(Context context) {
        SharedPreferences p = prefs(context);
        return p.contains(HASH) && p.contains(SALT) && p.contains(WRAPPED) && p.contains(WRAP_IV);
    }

    static boolean verifyPassword(Context context, String password) throws Exception {
        char[] characters = password.toCharArray();
        try {
            return verifyPassword(context, characters);
        } finally {
            Arrays.fill(characters, '\0');
        }
    }

    static boolean verifyPassword(Context context, char[] password) throws Exception {
        SharedPreferences p = prefs(context);
        byte[] salt = Base64.decode(p.getString(SALT, ""), Base64.NO_WRAP);
        byte[] expected = Base64.decode(p.getString(HASH, ""), Base64.NO_WRAP);
        byte[] actual = derive(password, salt);
        try {
            return MessageDigest.isEqual(expected, actual);
        } finally {
            Arrays.fill(actual, (byte) 0);
            Arrays.fill(expected, (byte) 0);
            Arrays.fill(salt, (byte) 0);
        }
    }

    static Cipher newWrappingCipherForSetup() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateBiometricKey());
        return cipher;
    }

    static Cipher newWrappingCipherForUnlock(Context context) throws Exception {
        byte[] iv = Base64.decode(prefs(context).getString(WRAP_IV, ""), Base64.NO_WRAP);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateBiometricKey(), new GCMParameterSpec(GCM_TAG_BITS, iv));
        return cipher;
    }

    static byte[] wrappedVaultKey(Context context) {
        return Base64.decode(prefs(context).getString(WRAPPED, ""), Base64.NO_WRAP);
    }

    static void saveNewCredentials(Context context, String password, byte[] wrapped, byte[] iv) throws Exception {
        byte[] salt = new byte[32];
        new SecureRandom().nextBytes(salt);
        byte[] hash = derive(password, salt);
        try {
            boolean saved = prefs(context).edit()
                    .putString(SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
                    .putString(HASH, Base64.encodeToString(hash, Base64.NO_WRAP))
                    .putString(WRAPPED, Base64.encodeToString(wrapped, Base64.NO_WRAP))
                    .putString(WRAP_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
                    .commit();
            if (!saved) throw new IllegalStateException("Could not save secure settings");
        } finally {
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(hash, (byte) 0);
        }
    }

    private static byte[] derive(String password, byte[] salt) throws Exception {
        char[] characters = password.toCharArray();
        try {
            return derive(characters, salt);
        } finally {
            Arrays.fill(characters, '\0');
        }
    }

    private static byte[] derive(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_BITS);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
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
        if (android.os.Build.VERSION.SDK_INT >= 30) {
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

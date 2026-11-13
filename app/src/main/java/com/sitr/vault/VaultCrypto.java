package com.sitr.vault;

import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

final class VaultCrypto {
    private static final int ITERATIONS = 310_000;
    private static final int KEY_BITS = 256;
    private static final int SALT_BYTES = 32;
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    static final int MIN_PASSWORD_CHARS = 8;

    private VaultCrypto() {}

    static VaultSession create(String vaultId, char[] password) throws Exception {
        if (password == null || password.length < MIN_PASSWORD_CHARS) {
            if (password != null) Arrays.fill(password, '\0');
            throw new IllegalArgumentException("Vault password must contain at least 8 characters");
        }
        byte[] salt = new byte[SALT_BYTES];
        new SecureRandom().nextBytes(salt);
        byte[] rawKey = derive(password, salt);
        SecretKeySpec key = new SecretKeySpec(rawKey, "AES");
        Arrays.fill(rawKey, (byte) 0);
        EncryptedVault vault = new EncryptedVault(vaultId);
        vault.salt = Base64.encodeToString(salt, Base64.NO_WRAP);
        List<VaultItem> items = new ArrayList<>();
        byte[] plain = null;
        byte[] encrypted = null;
        try {
            plain = serialize(items);
            encrypted = encryptPayload(vault.id, key, plain);
            vault.payload = Base64.encodeToString(encrypted, Base64.NO_WRAP);
            return new VaultSession(vault, key, items);
        } catch (Exception e) {
            clearKey(key);
            throw e;
        } finally {
            if (plain != null) Arrays.fill(plain, (byte) 0);
            if (encrypted != null) Arrays.fill(encrypted, (byte) 0);
            Arrays.fill(salt, (byte) 0);
        }
    }

    static VaultSession open(EncryptedVault vault, char[] password) throws Exception {
        if (vault == null || !vault.isInitialized()) throw new IllegalStateException("Vault is not initialized");
        byte[] salt = Base64.decode(vault.salt, Base64.NO_WRAP);
        byte[] rawKey = derive(password, salt);
        SecretKeySpec key = new SecretKeySpec(rawKey, "AES");
        Arrays.fill(rawKey, (byte) 0);
        Arrays.fill(salt, (byte) 0);
        byte[] payload = null;
        byte[] plain = null;
        try {
            payload = Base64.decode(vault.payload, Base64.NO_WRAP);
            plain = decryptPayload(vault.id, key, payload);
            List<VaultItem> items = parseItems(plain);
            return new VaultSession(vault.copy(), key, items);
        } catch (Exception e) {
            clearKey(key);
            throw e;
        } finally {
            if (payload != null) Arrays.fill(payload, (byte) 0);
            if (plain != null) Arrays.fill(plain, (byte) 0);
        }
    }

    static EncryptedVault reencrypt(EncryptedVault current, SecretKey key, List<VaultItem> items) throws Exception {
        if (current == null || key == null) throw new IllegalStateException("Vault is locked");
        byte[] plain = serialize(items);
        try {
            EncryptedVault updated = current.copy();
            updated.payload = Base64.encodeToString(encryptPayload(updated.id, key, plain), Base64.NO_WRAP);
            return updated;
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    static void verifyPassword(EncryptedVault vault, char[] password) throws Exception {
        VaultSession verified = open(vault, password);
        verified.destroy();
    }

    static byte[] derive(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_BITS);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
            Arrays.fill(password, '\0');
        }
    }

    static byte[] encryptPayload(String vaultId, SecretKey key, byte[] plaintext) throws Exception {
        byte[] iv = new byte[IV_BYTES];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        cipher.updateAAD(aad(vaultId));
        byte[] ciphertext = cipher.doFinal(plaintext);
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
        Arrays.fill(iv, (byte) 0);
        Arrays.fill(ciphertext, (byte) 0);
        return result;
    }

    static byte[] decryptPayload(String vaultId, SecretKey key, byte[] encrypted) throws Exception {
        if (encrypted == null || encrypted.length < IV_BYTES + 16) throw new IllegalStateException("Encrypted vault data is incomplete");
        byte[] iv = Arrays.copyOfRange(encrypted, 0, IV_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(encrypted, IV_BYTES, encrypted.length);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(aad(vaultId));
            return cipher.doFinal(ciphertext);
        } finally {
            Arrays.fill(iv, (byte) 0);
            Arrays.fill(ciphertext, (byte) 0);
        }
    }

    private static byte[] serialize(List<VaultItem> items) throws Exception {
        JSONArray array = new JSONArray();
        for (VaultItem item : items) array.put(item.toJson());
        return array.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static List<VaultItem> parseItems(byte[] plain) throws Exception {
        JSONArray array = new JSONArray(new String(plain, StandardCharsets.UTF_8));
        List<VaultItem> items = new ArrayList<>();
        for (int i = 0; i < array.length(); i++) {
            JSONObject object = array.optJSONObject(i);
            if (object != null) items.add(VaultItem.fromJson(object));
        }
        return items;
    }

    private static byte[] aad(String vaultId) {
        return ("sitr-vault-box-v2|" + vaultId).getBytes(StandardCharsets.UTF_8);
    }

    private static void clearKey(SecretKeySpec key) {
        if (key == null) return;
        byte[] bytes = key.getEncoded();
        if (bytes != null) Arrays.fill(bytes, (byte) 0);
    }
}

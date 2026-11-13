package com.sitr.vault;

import android.content.Context;
import android.net.Uri;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

final class VaultStore {
    private static final String FILE_NAME = "vault.sitr.enc";
    private static final String ATTACHMENT_DIRECTORY = "vault-attachments";
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    static final long MAX_ATTACHMENT_BYTES = 20L * 1024L * 1024L;

    private VaultStore() {}

    static List<VaultItem> load(Context context, SecretKey key) throws Exception {
        File file = dataFile(context);
        if (!file.exists()) return new ArrayList<>();
        byte[] encrypted = readFully(file);
        if (encrypted.length < IV_BYTES + 16) throw new IllegalStateException("Vault data is incomplete");
        byte[] iv = Arrays.copyOfRange(encrypted, 0, IV_BYTES);
        byte[] cipherText = Arrays.copyOfRange(encrypted, IV_BYTES, encrypted.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        byte[] plain = cipher.doFinal(cipherText);
        try {
            JSONArray array = new JSONArray(new String(plain, StandardCharsets.UTF_8));
            List<VaultItem> items = new ArrayList<>();
            for (int i = 0; i < array.length(); i++) {
                JSONObject object = array.optJSONObject(i);
                if (object != null) items.add(VaultItem.fromJson(object));
            }
            return items;
        } finally {
            Arrays.fill(plain, (byte) 0);
            Arrays.fill(encrypted, (byte) 0);
            Arrays.fill(iv, (byte) 0);
            Arrays.fill(cipherText, (byte) 0);
        }
    }

    static void save(Context context, SecretKey key, List<VaultItem> items) throws Exception {
        JSONArray array = new JSONArray();
        for (VaultItem item : items) array.put(item.toJson());
        byte[] plain = array.toString().getBytes(StandardCharsets.UTF_8);
        byte[] iv = new byte[IV_BYTES];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        byte[] cipherText = cipher.doFinal(plain);
        byte[] encrypted = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, encrypted, 0, iv.length);
        System.arraycopy(cipherText, 0, encrypted, iv.length, cipherText.length);

        File target = dataFile(context);
        File temp = new File(target.getParentFile(), FILE_NAME + ".tmp");
        try (FileOutputStream out = new FileOutputStream(temp, false)) {
            out.write(encrypted);
            out.getFD().sync();
        } finally {
            Arrays.fill(plain, (byte) 0);
            Arrays.fill(cipherText, (byte) 0);
            Arrays.fill(encrypted, (byte) 0);
            Arrays.fill(iv, (byte) 0);
        }
        moveAtomically(temp, target);
    }

    static VaultAttachment importAttachment(Context context, SecretKey key, Uri sourceUri,
                                               String name, String mimeType) throws Exception {
        File directory = attachmentDirectory(context);
        String id = UUID.randomUUID().toString();
        File target = new File(directory, id + ".enc");
        File temp = new File(directory, id + ".tmp");
        byte[] iv = new byte[IV_BYTES];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        long totalBytes = 0;
        boolean moved = false;
        try (InputStream in = context.getContentResolver().openInputStream(sourceUri);
             FileOutputStream out = new FileOutputStream(temp, false)) {
            if (in == null) throw new IOException("Cannot open selected document");
            out.write(iv);
            byte[] buffer = new byte[8192];
            try {
                int count;
                while ((count = in.read(buffer)) != -1) {
                    if (count == 0) continue;
                    totalBytes += count;
                    if (totalBytes > MAX_ATTACHMENT_BYTES) {
                        throw new IOException("Attachment exceeds 20 MB");
                    }
                    byte[] encryptedPart = cipher.update(buffer, 0, count);
                    if (encryptedPart != null) {
                        out.write(encryptedPart);
                        Arrays.fill(encryptedPart, (byte) 0);
                    }
                }
            } finally {
                Arrays.fill(buffer, (byte) 0);
            }
            byte[] finalPart = cipher.doFinal();
            if (finalPart != null) {
                out.write(finalPart);
                Arrays.fill(finalPart, (byte) 0);
            }
            out.getFD().sync();
        } catch (Exception e) {
            temp.delete();
            target.delete();
            Arrays.fill(iv, (byte) 0);
            throw e;
        }
        Arrays.fill(iv, (byte) 0);
        try {
            moveAtomically(temp, target);
            moved = true;
        } finally {
            if (!moved) {
                temp.delete();
                target.delete();
            }
        }
        VaultAttachment attachment = new VaultAttachment();
        attachment.id = id;
        attachment.name = (name == null || name.trim().isEmpty()) ? "مرفق" : name;
        attachment.mimeType = (mimeType == null || mimeType.trim().isEmpty())
                ? "application/octet-stream" : mimeType;
        attachment.sizeBytes = totalBytes;
        return attachment;
    }

    static void exportAttachment(Context context, SecretKey key, VaultAttachment attachment,
                                 Uri destinationUri) throws Exception {
        File source = attachmentFile(context, attachment.id);
        if (!source.exists()) throw new IOException("Attachment is missing from local storage");
        if (source.length() > MAX_ATTACHMENT_BYTES + IV_BYTES + 16L) {
            throw new IOException("Encrypted attachment size is invalid");
        }
        File plaintextTemp = new File(context.getCacheDir(), "sitr-export-" + UUID.randomUUID() + ".tmp");
        byte[] iv = new byte[IV_BYTES];
        try {
            try (FileInputStream in = new FileInputStream(source);
                 FileOutputStream plaintext = new FileOutputStream(plaintextTemp, false)) {
                readExactly(in, iv);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
                byte[] buffer = new byte[8192];
                try {
                    int count;
                    while ((count = in.read(buffer)) != -1) {
                        if (count == 0) continue;
                        byte[] plainPart = cipher.update(buffer, 0, count);
                        if (plainPart != null) {
                            plaintext.write(plainPart);
                            Arrays.fill(plainPart, (byte) 0);
                        }
                    }
                    byte[] finalPart = cipher.doFinal();
                    if (finalPart != null) {
                        plaintext.write(finalPart);
                        Arrays.fill(finalPart, (byte) 0);
                    }
                } finally {
                    Arrays.fill(buffer, (byte) 0);
                }
                plaintext.getFD().sync();
            }
            try (InputStream in = new FileInputStream(plaintextTemp);
                 OutputStream out = context.getContentResolver().openOutputStream(destinationUri, "w")) {
                if (out == null) throw new IOException("Cannot open export destination");
                byte[] buffer = new byte[8192];
                try {
                    int count;
                    while ((count = in.read(buffer)) != -1) {
                        if (count > 0) out.write(buffer, 0, count);
                    }
                    out.flush();
                } finally {
                    Arrays.fill(buffer, (byte) 0);
                }
            }
        } finally {
            Arrays.fill(iv, (byte) 0);
            plaintextTemp.delete();
        }
    }

    static void deleteAttachment(Context context, String attachmentId) throws IOException {
        File file = attachmentFile(context, attachmentId);
        if (file.exists() && !file.delete()) throw new IOException("Could not delete attachment");
    }

    private static File dataFile(Context context) {
        return new File(context.getNoBackupFilesDir(), FILE_NAME);
    }

    private static File attachmentDirectory(Context context) throws IOException {
        File directory = new File(context.getNoBackupFilesDir(), ATTACHMENT_DIRECTORY);
        if (!directory.exists() && !directory.mkdirs()) throw new IOException("Cannot create attachment directory");
        if (!directory.isDirectory()) throw new IOException("Attachment path is not a directory");
        return directory;
    }

    private static File attachmentFile(Context context, String id) throws IOException {
        if (id == null || !id.matches("[0-9a-fA-F-]{36}")) throw new IOException("Invalid attachment ID");
        return new File(attachmentDirectory(context), id + ".enc");
    }

    private static void moveAtomically(File source, File target) throws IOException {
        try {
            Files.move(source.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(source.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void readExactly(InputStream in, byte[] buffer) throws IOException {
        int offset = 0;
        while (offset < buffer.length) {
            int count = in.read(buffer, offset, buffer.length - offset);
            if (count < 0) throw new IOException("Encrypted attachment is incomplete");
            offset += count;
        }
    }

    private static byte[] readFully(File file) throws Exception {
        try (FileInputStream in = new FileInputStream(file)) {
            byte[] bytes = new byte[(int) file.length()];
            int offset = 0;
            while (offset < bytes.length) {
                int count = in.read(bytes, offset, bytes.length - offset);
                if (count < 0) break;
                offset += count;
            }
            if (offset != bytes.length) throw new IllegalStateException("Could not read complete vault file");
            return bytes;
        }
    }
}

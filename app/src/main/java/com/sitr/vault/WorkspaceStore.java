package com.sitr.vault;

import android.content.Context;

import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

final class WorkspaceStore {
    private static final String FILE_NAME = "workspace-v2.sitr.enc";
    private static final byte[] MAGIC = new byte[] {'S', 'I', 'T', 'R', 2};
    private static final byte[] AAD = "sitr-workspace-v2".getBytes(StandardCharsets.UTF_8);
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;

    private WorkspaceStore() {}

    static WorkspaceData load(Context context, SecretKey key) throws Exception {
        File file = dataFile(context);
        if (!file.exists()) return new WorkspaceData();
        byte[] encrypted = readFully(file);
        if (encrypted.length < MAGIC.length + IV_BYTES + 16) throw new IllegalStateException("Workspace file is incomplete");
        for (int i = 0; i < MAGIC.length; i++) {
            if (encrypted[i] != MAGIC[i]) throw new IllegalStateException("Unsupported workspace file version");
        }
        byte[] iv = Arrays.copyOfRange(encrypted, MAGIC.length, MAGIC.length + IV_BYTES);
        byte[] cipherText = Arrays.copyOfRange(encrypted, MAGIC.length + IV_BYTES, encrypted.length);
        byte[] plain = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(AAD);
            plain = cipher.doFinal(cipherText);
            WorkspaceData data = WorkspaceData.fromJson(new JSONObject(new String(plain, StandardCharsets.UTF_8)));
            if (data.needsMigration) {
                try {
                    save(context, key, data);
                } catch (Exception ignoredMigrationFailure) {
                    File temp = new File(file.getParentFile(), FILE_NAME + ".tmp");
                    if (temp.exists()) temp.delete();
                }
            }
            return data;
        } finally {
            Arrays.fill(encrypted, (byte) 0);
            Arrays.fill(iv, (byte) 0);
            Arrays.fill(cipherText, (byte) 0);
            if (plain != null) Arrays.fill(plain, (byte) 0);
        }
    }

    static void save(Context context, SecretKey key, WorkspaceData data) throws Exception {
        byte[] plain = data.toJson().toString().getBytes(StandardCharsets.UTF_8);
        byte[] iv = new byte[IV_BYTES];
        new SecureRandom().nextBytes(iv);
        byte[] cipherText = null;
        byte[] encrypted = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(AAD);
            cipherText = cipher.doFinal(plain);
            encrypted = new byte[MAGIC.length + iv.length + cipherText.length];
            System.arraycopy(MAGIC, 0, encrypted, 0, MAGIC.length);
            System.arraycopy(iv, 0, encrypted, MAGIC.length, iv.length);
            System.arraycopy(cipherText, 0, encrypted, MAGIC.length + iv.length, cipherText.length);
            File target = dataFile(context);
            File temp = new File(target.getParentFile(), FILE_NAME + ".tmp");
            try (FileOutputStream out = new FileOutputStream(temp, false)) {
                out.write(encrypted);
                out.getFD().sync();
            }
            moveAtomically(temp, target);
            data.needsMigration = false;
            for (Project project : data.projects) project.migratedLegacyFiles = false;
        } finally {
            Arrays.fill(plain, (byte) 0);
            Arrays.fill(iv, (byte) 0);
            if (cipherText != null) Arrays.fill(cipherText, (byte) 0);
            if (encrypted != null) Arrays.fill(encrypted, (byte) 0);
        }
    }

    static void deleteWorkspace(Context context) {
        File file = dataFile(context);
        if (file.exists()) file.delete();
        File temp = new File(file.getParentFile(), FILE_NAME + ".tmp");
        if (temp.exists()) temp.delete();
    }

    private static File dataFile(Context context) {
        return new File(context.getNoBackupFilesDir(), FILE_NAME);
    }

    private static void moveAtomically(File source, File target) throws Exception {
        try {
            Files.move(source.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(source.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static byte[] readFully(File file) throws Exception {
        try (FileInputStream input = new FileInputStream(file)) {
            byte[] bytes = new byte[(int) file.length()];
            int offset = 0;
            while (offset < bytes.length) {
                int count = input.read(bytes, offset, bytes.length - offset);
                if (count < 0) break;
                offset += count;
            }
            if (offset != bytes.length) throw new IllegalStateException("Could not read full workspace");
            return bytes;
        }
    }
}

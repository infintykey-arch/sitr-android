package com.sitr.vault;

import android.content.Context;
import android.net.Uri;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
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
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

final class LocalFileStore {
    static final long MAX_FILE_BYTES = 512L * 1024L * 1024L;
    private static final String DIRECTORY = "sitr-files-v2";
    private static final String OPEN_CACHE_DIRECTORY = "sitr-open";
    private static final byte[] MAGIC = new byte[] {'S', 'F', 'I', 'L', 2};
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;

    private LocalFileStore() {}

    static VaultAttachment importFile(Context context, SecretKey key, String ownerId, Uri sourceUri,
                                      String name, String mimeType) throws Exception {
        try (InputStream input = context.getContentResolver().openInputStream(sourceUri)) {
            if (input == null) throw new IOException("Cannot open selected file");
            return importStream(context, key, ownerId, input, name, mimeType, MAX_FILE_BYTES);
        }
    }

    static VaultAttachment importBytes(Context context, SecretKey key, String ownerId, byte[] bytes,
                                       String name, String mimeType) throws Exception {
        if (bytes == null) throw new IOException("No file content");
        try (InputStream input = new ByteArrayInputStream(bytes)) {
            return importStream(context, key, ownerId, input, name, mimeType, MAX_FILE_BYTES);
        }
    }

    private static VaultAttachment importStream(Context context, SecretKey key, String ownerId, InputStream input,
                                                String name, String mimeType, long maxBytes) throws Exception {
        if (key == null || maxBytes < 0L) throw new IOException("Invalid file import parameters");
        File ownerDirectory = ownerDirectory(context, ownerId, true);
        String attachmentId = UUID.randomUUID().toString();
        File target = new File(ownerDirectory, attachmentId + ".enc");
        File temp = new File(ownerDirectory, attachmentId + ".tmp");
        byte[] iv = new byte[IV_BYTES];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        cipher.updateAAD(aad(ownerId, attachmentId));
        long totalBytes = 0L;
        boolean moved = false;
        try (FileOutputStream output = new FileOutputStream(temp, false)) {
            output.write(MAGIC);
            output.write(iv);
            byte[] buffer = new byte[32 * 1024];
            try {
                int count;
                while ((count = input.read(buffer)) != -1) {
                    if (count == 0) continue;
                    totalBytes += count;
                    if (totalBytes > maxBytes || totalBytes > MAX_FILE_BYTES) throw new IOException("File exceeds its size limit");
                    byte[] part = cipher.update(buffer, 0, count);
                    if (part != null) {
                        output.write(part);
                        Arrays.fill(part, (byte) 0);
                    }
                }
            } finally {
                Arrays.fill(buffer, (byte) 0);
            }
            byte[] finalPart = cipher.doFinal();
            output.write(finalPart);
            Arrays.fill(finalPart, (byte) 0);
            output.getFD().sync();
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
        attachment.id = attachmentId;
        attachment.name = safeDisplayName(name);
        attachment.mimeType = FileSupport.mimeTypeForName(attachment.name, mimeType);
        attachment.sizeBytes = totalBytes;
        return attachment;
    }

    static void exportFile(Context context, SecretKey key, String ownerId, VaultAttachment attachment,
                           Uri destination) throws Exception {
        File source = attachmentFile(context, ownerId, attachment.id);
        validateEncryptedFile(source);
        File temp = new File(context.getCacheDir(), "sitr-export-" + UUID.randomUUID() + ".tmp");
        byte[] iv = new byte[IV_BYTES];
        try {
            try (FileInputStream input = new FileInputStream(source);
                 FileOutputStream output = new FileOutputStream(temp, false)) {
                readAndCheckHeader(input, iv);
                Cipher cipher = decryptCipher(key, ownerId, attachment.id, iv);
                copyDecrypted(input, output, cipher, MAX_FILE_BYTES);
                output.getFD().sync();
            }
            try (InputStream input = new FileInputStream(temp);
                 OutputStream output = context.getContentResolver().openOutputStream(destination, "w")) {
                if (output == null) throw new IOException("Cannot open export destination");
                transfer(input, output);
                output.flush();
            }
        } finally {
            Arrays.fill(iv, (byte) 0);
            temp.delete();
        }
    }

    static void exportFilesZip(Context context, SecretKey key, String ownerId,
                               List<VaultAttachment> attachments, Uri destination) throws Exception {
        if (attachments == null || attachments.isEmpty()) throw new IOException("No selected files");
        OutputStream raw = context.getContentResolver().openOutputStream(destination, "w");
        if (raw == null) throw new IOException("Cannot open ZIP destination");
        Set<String> usedNames = new HashSet<>();
        try (ZipOutputStream zip = new ZipOutputStream(new BufferedOutputStream(raw))) {
            for (VaultAttachment attachment : attachments) {
                String entryName = FileSupport.uniqueFlatZipName(attachment.name, usedNames);
                zip.putNextEntry(new ZipEntry(entryName));
                streamDecryptedFileToZip(context, key, ownerId, attachment, zip);
                zip.closeEntry();
            }
            zip.finish();
        }
    }

    private static void streamDecryptedFileToZip(Context context, SecretKey key, String ownerId,
                                                 VaultAttachment attachment, ZipOutputStream zip) throws Exception {
        File source = attachmentFile(context, ownerId, attachment.id);
        validateEncryptedFile(source);
        byte[] iv = new byte[IV_BYTES];
        try (FileInputStream input = new FileInputStream(source)) {
            readAndCheckHeader(input, iv);
            Cipher cipher = decryptCipher(key, ownerId, attachment.id, iv);
            byte[] buffer = new byte[32 * 1024];
            long total = 0L;
            try {
                int count;
                while ((count = input.read(buffer)) != -1) {
                    if (count == 0) continue;
                    byte[] plain = cipher.update(buffer, 0, count);
                    if (plain != null) {
                        total += plain.length;
                        if (total > MAX_FILE_BYTES) throw new IOException("File exceeds 512 MB");
                        zip.write(plain);
                        Arrays.fill(plain, (byte) 0);
                    }
                }
                byte[] finalPlain = cipher.doFinal();
                total += finalPlain.length;
                if (total > MAX_FILE_BYTES) throw new IOException("File exceeds 512 MB");
                zip.write(finalPlain);
                Arrays.fill(finalPlain, (byte) 0);
            } finally {
                Arrays.fill(buffer, (byte) 0);
            }
        } finally {
            Arrays.fill(iv, (byte) 0);
        }
    }

    static VaultAttachment copyReencrypted(Context context, SecretKey sourceKey, String sourceOwnerId,
                                           VaultAttachment sourceAttachment, SecretKey destinationKey,
                                           String destinationOwnerId) throws Exception {
        File source = attachmentFile(context, sourceOwnerId, sourceAttachment.id);
        validateEncryptedFile(source);
        File destinationDirectory = ownerDirectory(context, destinationOwnerId, true);
        String destinationId = UUID.randomUUID().toString();
        File target = new File(destinationDirectory, destinationId + ".enc");
        File temp = new File(destinationDirectory, destinationId + ".tmp");
        byte[] sourceIv = new byte[IV_BYTES];
        byte[] destinationIv = new byte[IV_BYTES];
        new SecureRandom().nextBytes(destinationIv);
        boolean moved = false;
        try {
            try (FileInputStream input = new FileInputStream(source);
                 FileOutputStream output = new FileOutputStream(temp, false)) {
                readAndCheckHeader(input, sourceIv);
                Cipher decrypt = decryptCipher(sourceKey, sourceOwnerId, sourceAttachment.id, sourceIv);
                Cipher encrypt = Cipher.getInstance("AES/GCM/NoPadding");
                encrypt.init(Cipher.ENCRYPT_MODE, destinationKey, new GCMParameterSpec(TAG_BITS, destinationIv));
                encrypt.updateAAD(aad(destinationOwnerId, destinationId));
                output.write(MAGIC);
                output.write(destinationIv);
                byte[] buffer = new byte[32 * 1024];
                long total = 0L;
                try {
                    int count;
                    while ((count = input.read(buffer)) != -1) {
                        if (count == 0) continue;
                        byte[] plain = decrypt.update(buffer, 0, count);
                        if (plain != null) {
                            total += plain.length;
                            if (total > MAX_FILE_BYTES) throw new IOException("File exceeds 512 MB");
                            byte[] encrypted = encrypt.update(plain);
                            if (encrypted != null) {
                                output.write(encrypted);
                                Arrays.fill(encrypted, (byte) 0);
                            }
                            Arrays.fill(plain, (byte) 0);
                        }
                    }
                    byte[] finalPlain = decrypt.doFinal();
                    total += finalPlain.length;
                    if (total > MAX_FILE_BYTES) throw new IOException("File exceeds 512 MB");
                    byte[] finalCipher = encrypt.doFinal(finalPlain);
                    output.write(finalCipher);
                    Arrays.fill(finalPlain, (byte) 0);
                    Arrays.fill(finalCipher, (byte) 0);
                } finally {
                    Arrays.fill(buffer, (byte) 0);
                }
                output.getFD().sync();
                VaultAttachment copied = new VaultAttachment();
                copied.id = destinationId;
                copied.name = safeDisplayName(sourceAttachment.name);
                copied.mimeType = FileSupport.mimeTypeForName(copied.name, sourceAttachment.mimeType);
                copied.sizeBytes = total;
                moveAtomically(temp, target);
                moved = true;
                return copied;
            }
        } finally {
            Arrays.fill(sourceIv, (byte) 0);
            Arrays.fill(destinationIv, (byte) 0);
            if (!moved) {
                temp.delete();
                target.delete();
            }
        }
    }

    static File decryptToCacheFile(Context context, SecretKey key, String ownerId,
                                   VaultAttachment attachment) throws Exception {
        File source = attachmentFile(context, ownerId, attachment.id);
        validateEncryptedFile(source);
        File cacheDirectory = new File(context.getCacheDir(), OPEN_CACHE_DIRECTORY);
        if (!cacheDirectory.exists() && !cacheDirectory.mkdirs()) throw new IOException("Cannot create open cache");
        String extension = safeExtension(attachment.name);
        File target = new File(cacheDirectory, "sitr-open-" + UUID.randomUUID() + extension);
        File temp = new File(cacheDirectory, target.getName() + ".tmp");
        byte[] iv = new byte[IV_BYTES];
        try {
            try (FileInputStream input = new FileInputStream(source);
                 FileOutputStream output = new FileOutputStream(temp, false)) {
                readAndCheckHeader(input, iv);
                Cipher cipher = decryptCipher(key, ownerId, attachment.id, iv);
                copyDecrypted(input, output, cipher, MAX_FILE_BYTES);
                output.getFD().sync();
            }
            moveAtomically(temp, target);
            return target;
        } catch (Exception e) {
            temp.delete();
            target.delete();
            throw e;
        } finally {
            Arrays.fill(iv, (byte) 0);
        }
    }

    static byte[] readDecryptedBytes(Context context, SecretKey key, String ownerId,
                                     VaultAttachment attachment, long maxBytes) throws Exception {
        if (attachment.sizeBytes > maxBytes || maxBytes > MAX_FILE_BYTES) throw new IOException("File is too large to edit");
        File source = attachmentFile(context, ownerId, attachment.id);
        validateEncryptedFile(source);
        byte[] iv = new byte[IV_BYTES];
        try (FileInputStream input = new FileInputStream(source);
             ByteArrayOutputStream output = new ByteArrayOutputStream((int) Math.max(0L, attachment.sizeBytes))) {
            readAndCheckHeader(input, iv);
            Cipher cipher = decryptCipher(key, ownerId, attachment.id, iv);
            copyDecrypted(input, output, cipher, maxBytes);
            return output.toByteArray();
        } finally {
            Arrays.fill(iv, (byte) 0);
        }
    }

    static List<VaultAttachment> extractZip(Context context, SecretKey key, String ownerId,
                                            VaultAttachment archive) throws Exception {
        File plainZip = decryptToCacheFile(context, key, ownerId, archive);
        List<VaultAttachment> created = new ArrayList<>();
        long totalBytes = 0L;
        int entries = 0;
        try (ZipInputStream zip = new ZipInputStream(new BufferedInputStream(new FileInputStream(plainZip)))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                entries++;
                if (entries > FileSupport.MAX_ZIP_ENTRIES) throw new IOException("ZIP has too many entries");
                String safeName = FileSupport.safeZipEntryName(entry.getName());
                if (safeName == null) throw new IOException("ZIP contains an unsafe path");
                if (!entry.isDirectory()) {
                    long remaining = FileSupport.MAX_ZIP_TOTAL_BYTES - totalBytes;
                    if (remaining < 0L) throw new IOException("ZIP exceeds its total extraction size limit");
                    String mime = FileSupport.mimeTypeForName(safeName, "application/octet-stream");
                    VaultAttachment extracted = importStream(context, key, ownerId, zip, safeName, mime,
                            Math.min(MAX_FILE_BYTES, remaining));
                    totalBytes += extracted.sizeBytes;
                    created.add(extracted);
                }
                zip.closeEntry();
            }
            if (created.isEmpty()) throw new IOException("ZIP contains no files");
            return created;
        } catch (Exception e) {
            for (VaultAttachment file : created) {
                try { deleteFile(context, ownerId, file.id); } catch (Exception ignored) { }
            }
            throw e;
        } finally {
            plainZip.delete();
        }
    }

    static void deleteFile(Context context, String ownerId, String attachmentId) throws IOException {
        File file = attachmentFile(context, ownerId, attachmentId);
        if (file.exists() && !file.delete()) throw new IOException("Could not delete encrypted file");
    }

    static boolean deleteOwner(Context context, String ownerId) {
        try {
            File directory = ownerDirectory(context, ownerId, false);
            return deleteTree(directory);
        } catch (IOException ignored) {
            return false;
        }
    }

    static void cleanupTemporaryFiles(Context context) {
        File cache = context.getCacheDir();
        File[] exports = cache.listFiles((dir, name) -> name.startsWith("sitr-export-") && name.endsWith(".tmp"));
        if (exports != null) for (File file : exports) file.delete();
        File openCache = new File(cache, OPEN_CACHE_DIRECTORY);
        deleteTree(openCache);
        File root = new File(context.getNoBackupFilesDir(), DIRECTORY);
        cleanupEncryptedTemps(root);
    }

    private static void cleanupEncryptedTemps(File directory) {
        if (directory == null || !directory.exists()) return;
        File[] files = directory.listFiles();
        if (files == null) return;
        for (File file : files) {
            if (file.isDirectory()) cleanupEncryptedTemps(file);
            else if (file.getName().endsWith(".tmp")) file.delete();
        }
    }

    private static File ownerDirectory(Context context, String ownerId, boolean create) throws IOException {
        if (ownerId == null || !ownerId.matches("[A-Za-z0-9_-]{1,80}")) throw new IOException("Invalid file owner ID");
        File root = new File(context.getNoBackupFilesDir(), DIRECTORY);
        File directory = new File(root, ownerId);
        if (create) {
            if (!directory.exists() && !directory.mkdirs()) throw new IOException("Cannot create local file directory");
            if (!directory.isDirectory()) throw new IOException("Local file path is invalid");
        }
        return directory;
    }

    private static File attachmentFile(Context context, String ownerId, String attachmentId) throws IOException {
        if (attachmentId == null || !attachmentId.matches("[0-9a-fA-F-]{36}")) throw new IOException("Invalid file ID");
        return new File(ownerDirectory(context, ownerId, false), attachmentId + ".enc");
    }

    private static void validateEncryptedFile(File source) throws IOException {
        long headerBytes = MAGIC.length + IV_BYTES;
        if (!source.exists() || source.length() < headerBytes + 16L
                || source.length() > headerBytes + MAX_FILE_BYTES + 16L) {
            throw new IOException("Encrypted file is missing or has invalid size");
        }
    }

    private static void readAndCheckHeader(InputStream input, byte[] iv) throws IOException {
        byte[] magic = new byte[MAGIC.length];
        readExactly(input, magic);
        if (!Arrays.equals(magic, MAGIC)) throw new IOException("Unsupported encrypted file format");
        readExactly(input, iv);
        Arrays.fill(magic, (byte) 0);
    }

    private static Cipher decryptCipher(SecretKey key, String ownerId, String attachmentId, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        cipher.updateAAD(aad(ownerId, attachmentId));
        return cipher;
    }

    private static long copyDecrypted(InputStream input, OutputStream output, Cipher cipher, long maxBytes) throws Exception {
        byte[] buffer = new byte[32 * 1024];
        long total = 0L;
        try {
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (count == 0) continue;
                byte[] part = cipher.update(buffer, 0, count);
                if (part != null) {
                    total += part.length;
                    if (total > maxBytes || total > MAX_FILE_BYTES) throw new IOException("Decrypted file exceeds its limit");
                    output.write(part);
                    Arrays.fill(part, (byte) 0);
                }
            }
            byte[] finalPart = cipher.doFinal();
            total += finalPart.length;
            if (total > maxBytes || total > MAX_FILE_BYTES) throw new IOException("Decrypted file exceeds its limit");
            output.write(finalPart);
            Arrays.fill(finalPart, (byte) 0);
            return total;
        } finally {
            Arrays.fill(buffer, (byte) 0);
        }
    }

    private static void transfer(InputStream input, OutputStream output) throws IOException {
        byte[] buffer = new byte[32 * 1024];
        try {
            int count;
            while ((count = input.read(buffer)) != -1) if (count > 0) output.write(buffer, 0, count);
        } finally {
            Arrays.fill(buffer, (byte) 0);
        }
    }

    private static byte[] aad(String ownerId, String attachmentId) {
        return ("sitr-file-v2|" + ownerId + "|" + attachmentId).getBytes(StandardCharsets.UTF_8);
    }

    private static String safeDisplayName(String name) {
        if (name == null || name.trim().isEmpty()) return "ملف";
        return name.replace('\n', ' ').replace('\r', ' ').trim();
    }

    private static String safeExtension(String name) {
        if (name == null) return ".bin";
        String base = name.replace('\\', '/');
        int slash = base.lastIndexOf('/');
        if (slash >= 0) base = base.substring(slash + 1);
        int dot = base.lastIndexOf('.');
        if (dot < 0 || base.length() - dot > 12) return ".bin";
        String extension = base.substring(dot);
        return extension.matches("\\.[A-Za-z0-9]{1,10}") ? extension : ".bin";
    }

    private static void readExactly(InputStream input, byte[] bytes) throws IOException {
        int offset = 0;
        while (offset < bytes.length) {
            int count = input.read(bytes, offset, bytes.length - offset);
            if (count < 0) throw new IOException("Encrypted file is incomplete");
            offset += count;
        }
    }

    private static void moveAtomically(File source, File target) throws IOException {
        try {
            Files.move(source.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(source.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static boolean deleteTree(File file) {
        if (file == null || !file.exists()) return true;
        File[] children = file.listFiles();
        if (children != null) {
            for (File child : children) if (!deleteTree(child)) return false;
        }
        return file.delete() || !file.exists();
    }
}

package com.sitr.vault;

import java.util.Locale;
import java.util.Set;

final class FileSupport {
    static final long MAX_EDIT_BYTES = 1024L * 1024L;
    static final long MAX_ZIP_TOTAL_BYTES = 1024L * 1024L * 1024L;
    static final int MAX_ZIP_ENTRIES = 1000;

    private FileSupport() {}

    static boolean isZip(String name, String mimeType) {
        String lower = safeLower(name);
        String mime = safeLower(mimeType);
        return lower.endsWith(".zip") || mime.equals("application/zip")
                || mime.equals("application/x-zip-compressed");
    }

    static boolean isApk(String name, String mimeType) {
        return safeLower(name).endsWith(".apk")
                || safeLower(mimeType).equals("application/vnd.android.package-archive");
    }

    static boolean isPdfOrWord(String name, String mimeType) {
        String lower = safeLower(name);
        String mime = safeLower(mimeType);
        return lower.endsWith(".pdf") || lower.endsWith(".doc") || lower.endsWith(".docx")
                || mime.equals("application/pdf") || mime.equals("application/msword")
                || mime.equals("application/vnd.openxmlformats-officedocument.wordprocessingml.document");
    }

    static boolean isEditableText(String name, String mimeType) {
        String lower = safeLower(name);
        int dot = lower.lastIndexOf('.');
        String extension = dot >= 0 ? lower.substring(dot) : "";
        switch (extension) {
            case ".txt": case ".md": case ".markdown": case ".csv": case ".json":
            case ".xml": case ".java": case ".kt": case ".kts": case ".js":
            case ".ts": case ".html": case ".css": case ".py": case ".sh":
            case ".yml": case ".yaml": case ".gradle": case ".properties":
            case ".sql": case ".c": case ".h": case ".cpp": case ".dart":
            case ".go": case ".rs": case ".rb": case ".php": case ".toml":
            case ".ini": case ".log": case ".jsx": case ".tsx":
                return true;
            default:
                return safeLower(mimeType).startsWith("text/");
        }
    }

    static String mimeTypeForName(String name, String fallback) {
        String lower = safeLower(name);
        if (lower.endsWith(".pdf")) return "application/pdf";
        if (lower.endsWith(".doc")) return "application/msword";
        if (lower.endsWith(".docx")) return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
        if (lower.endsWith(".apk")) return "application/vnd.android.package-archive";
        if (lower.endsWith(".zip")) return "application/zip";
        if (lower.endsWith(".json")) return "application/json";
        if (lower.endsWith(".xml")) return "application/xml";
        if (lower.endsWith(".html") || lower.endsWith(".htm")) return "text/html";
        if (lower.endsWith(".csv")) return "text/csv";
        if (lower.endsWith(".md")) return "text/markdown";
        if (isEditableText(name, null)) return "text/plain";
        return fallback == null || fallback.trim().isEmpty() ? "application/octet-stream" : fallback;
    }

    static String safeZipEntryName(String rawName) {
        if (rawName == null || rawName.trim().isEmpty()) return null;
        String normalized = rawName.replace('\\', '/').trim();
        if (normalized.startsWith("/") || normalized.matches("^[A-Za-z]:.*") || normalized.length() > 240) return null;
        String[] parts = normalized.split("/", -1);
        StringBuilder safe = new StringBuilder();
        for (String part : parts) {
            if (part.isEmpty()) continue;
            if (part.equals(".") || part.equals("..") || part.indexOf(':') >= 0) return null;
            for (int i = 0; i < part.length(); i++) {
                char c = part.charAt(i);
                if (Character.isISOControl(c)) return null;
            }
            if (safe.length() > 0) safe.append('/');
            safe.append(part);
        }
        return safe.length() == 0 ? null : safe.toString();
    }

    static String uniqueFlatZipName(String rawName, Set<String> usedNames) {
        String name = rawName == null ? "" : rawName.replace('\\', '/');
        int slash = name.lastIndexOf('/');
        if (slash >= 0) name = name.substring(slash + 1);
        name = name.replace('\n', '_').replace('\r', '_').trim();
        if (name.isEmpty() || name.equals(".") || name.equals("..")) name = "file";
        String candidate = name;
        int dot = name.lastIndexOf('.');
        String base = dot > 0 ? name.substring(0, dot) : name;
        String extension = dot > 0 ? name.substring(dot) : "";
        int suffix = 2;
        while (usedNames.contains(candidate.toLowerCase(Locale.ROOT))) {
            candidate = base + " (" + suffix++ + ")" + extension;
        }
        usedNames.add(candidate.toLowerCase(Locale.ROOT));
        return candidate;
    }

    private static String safeLower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT).trim();
    }
}

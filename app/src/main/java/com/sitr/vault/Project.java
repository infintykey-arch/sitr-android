package com.sitr.vault;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

final class Project {
    String id = UUID.randomUUID().toString();
    String name = "";
    int color;
    final List<ProjectVersion> versions = new ArrayList<>();
    String selectedVersionId;
    EncryptedVault secretVault;
    boolean migratedLegacyFiles;

    Project() {
        ProjectVersion initial = new ProjectVersion("الإصدار الأول");
        versions.add(initial);
        selectedVersionId = initial.id;
    }

    ProjectVersion selectedVersion() {
        if (versions.isEmpty()) {
            ProjectVersion initial = new ProjectVersion("الإصدار الأول");
            versions.add(initial);
            selectedVersionId = initial.id;
        }
        for (ProjectVersion version : versions) {
            if (version.id.equals(selectedVersionId)) return version;
        }
        selectedVersionId = versions.get(0).id;
        return versions.get(0);
    }

    ProjectVersion findVersion(String versionId) {
        if (versionId == null) return null;
        for (ProjectVersion version : versions) if (version.id.equals(versionId)) return version;
        return null;
    }

    boolean hasVersionName(String candidate) {
        String normalized = candidate == null ? "" : candidate.trim().toLowerCase(Locale.ROOT);
        for (ProjectVersion version : versions) {
            if (version.name.trim().toLowerCase(Locale.ROOT).equals(normalized)) return true;
        }
        return false;
    }

    ProjectVersion addVersion(String versionName) {
        ProjectVersion version = new ProjectVersion(versionName);
        versions.add(version);
        selectedVersionId = version.id;
        return version;
    }

    JSONObject toJson() throws JSONException {
        JSONObject object = new JSONObject();
        object.put("id", id);
        object.put("name", name);
        object.put("color", color);
        JSONArray versionArray = new JSONArray();
        for (ProjectVersion version : versions) versionArray.put(version.toJson());
        object.put("versions", versionArray);
        object.put("selectedVersionId", selectedVersionId);
        if (secretVault != null) object.put("secretVault", secretVault.toJson());
        return object;
    }

    static Project fromJson(JSONObject object) {
        Project project = new Project();
        project.versions.clear();
        project.id = object.optString("id", UUID.randomUUID().toString());
        project.name = object.optString("name", "مشروع");
        project.color = object.optInt("color", 0);

        JSONArray versionArray = object.optJSONArray("versions");
        if (versionArray != null) {
            for (int i = 0; i < versionArray.length(); i++) {
                JSONObject version = versionArray.optJSONObject(i);
                if (version != null) project.versions.add(ProjectVersion.fromJson(version));
            }
        }

        JSONArray legacyFiles = object.optJSONArray("files");
        if (project.versions.isEmpty()) {
            ProjectVersion migrated = new ProjectVersion(
                    legacyFiles != null && legacyFiles.length() > 0 ? "الإصدار الحالي" : "الإصدار الأول");
            appendFiles(legacyFiles, migrated.files);
            project.versions.add(migrated);
            project.migratedLegacyFiles = true;
        } else if (legacyFiles != null) {
            project.migratedLegacyFiles = true;
            ProjectVersion destination = project.versions.get(0);
            for (int i = 0; i < legacyFiles.length(); i++) {
                JSONObject file = legacyFiles.optJSONObject(i);
                if (file == null) continue;
                VaultAttachment attachment = VaultAttachment.fromJson(file);
                if (!containsFileId(project.versions, attachment.id)) destination.files.add(attachment);
            }
        }

        project.selectedVersionId = object.optString("selectedVersionId", "");
        if (project.findVersion(project.selectedVersionId) == null) {
            project.selectedVersionId = project.versions.get(0).id;
        }
        JSONObject vault = object.optJSONObject("secretVault");
        if (vault != null) project.secretVault = EncryptedVault.fromJson(vault);
        return project;
    }

    private static void appendFiles(JSONArray source, List<VaultAttachment> target) {
        if (source == null) return;
        for (int i = 0; i < source.length(); i++) {
            JSONObject file = source.optJSONObject(i);
            if (file != null) target.add(VaultAttachment.fromJson(file));
        }
    }

    private static boolean containsFileId(List<ProjectVersion> versions, String id) {
        for (ProjectVersion version : versions) {
            for (VaultAttachment file : version.files) if (file.id.equals(id)) return true;
        }
        return false;
    }
}

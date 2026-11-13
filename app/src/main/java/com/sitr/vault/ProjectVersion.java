package com.sitr.vault;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

final class ProjectVersion {
    String id = UUID.randomUUID().toString();
    String name = "";
    long createdAtMillis = System.currentTimeMillis();
    final List<VaultAttachment> files = new ArrayList<>();

    ProjectVersion() {}

    ProjectVersion(String name) {
        this.name = name == null ? "" : name.trim();
    }

    JSONObject toJson() throws JSONException {
        JSONObject object = new JSONObject();
        object.put("id", id);
        object.put("name", name);
        object.put("createdAtMillis", createdAtMillis);
        JSONArray fileArray = new JSONArray();
        for (VaultAttachment file : files) fileArray.put(file.toJson());
        object.put("files", fileArray);
        return object;
    }

    static ProjectVersion fromJson(JSONObject object) {
        ProjectVersion version = new ProjectVersion();
        version.id = object.optString("id", UUID.randomUUID().toString());
        if (version.id.trim().isEmpty()) version.id = UUID.randomUUID().toString();
        version.name = object.optString("name", "إصدار");
        if (version.name.trim().isEmpty()) version.name = "إصدار";
        version.createdAtMillis = object.optLong("createdAtMillis", System.currentTimeMillis());
        JSONArray fileArray = object.optJSONArray("files");
        if (fileArray != null) {
            for (int i = 0; i < fileArray.length(); i++) {
                JSONObject file = fileArray.optJSONObject(i);
                if (file != null) version.files.add(VaultAttachment.fromJson(file));
            }
        }
        return version;
    }
}

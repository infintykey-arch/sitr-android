package com.sitr.vault;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

final class WorkspaceData {
    static final int SCHEMA_VERSION = 3;
    private static final int LEGACY_SCHEMA_VERSION = 2;
    final List<Project> projects = new ArrayList<>();
    EncryptedVault generalVault;
    boolean needsMigration;

    JSONObject toJson() throws JSONException {
        JSONObject object = new JSONObject();
        object.put("schemaVersion", SCHEMA_VERSION);
        JSONArray projectArray = new JSONArray();
        for (Project project : projects) projectArray.put(project.toJson());
        object.put("projects", projectArray);
        if (generalVault != null) object.put("generalVault", generalVault.toJson());
        return object;
    }

    static WorkspaceData fromJson(JSONObject object) {
        int schemaVersion = object.optInt("schemaVersion", -1);
        if (schemaVersion != LEGACY_SCHEMA_VERSION && schemaVersion != SCHEMA_VERSION) {
            throw new IllegalStateException("Unsupported workspace format");
        }
        WorkspaceData data = new WorkspaceData();
        data.needsMigration = schemaVersion != SCHEMA_VERSION;
        JSONArray projectArray = object.optJSONArray("projects");
        if (projectArray != null) {
            for (int i = 0; i < projectArray.length(); i++) {
                JSONObject project = projectArray.optJSONObject(i);
                if (project != null) {
                    Project parsed = Project.fromJson(project);
                    data.projects.add(parsed);
                    data.needsMigration |= parsed.migratedLegacyFiles;
                }
            }
        }
        JSONObject vault = object.optJSONObject("generalVault");
        if (vault != null) data.generalVault = EncryptedVault.fromJson(vault);
        return data;
    }
}

package com.sitr.vault;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class ProjectVersionMigrationTest {
    @Test public void schemaTwoFilesMigrateOnceAndKeepProjectVault() throws Exception {
        VaultAttachment legacyFile = attachment("11111111-1111-4111-8111-111111111111", "source.zip", 1234L);
        JSONObject legacyProject = new JSONObject();
        legacyProject.put("id", "project-alpha");
        legacyProject.put("name", "Alpha");
        legacyProject.put("color", 12);
        legacyProject.put("files", new JSONArray().put(legacyFile.toJson()));
        JSONObject originalVault = new JSONObject();
        originalVault.put("id", "project-vault-project-alpha");
        originalVault.put("salt", "kept-salt");
        originalVault.put("payload", "kept-encrypted-payload");
        legacyProject.put("secretVault", originalVault);
        JSONObject legacyWorkspace = new JSONObject();
        legacyWorkspace.put("schemaVersion", 2);
        legacyWorkspace.put("projects", new JSONArray().put(legacyProject));

        WorkspaceData migrated = WorkspaceData.fromJson(legacyWorkspace);

        assertTrue(migrated.needsMigration);
        assertEquals(1, migrated.projects.size());
        Project project = migrated.projects.get(0);
        assertEquals(1, project.versions.size());
        assertEquals("الإصدار الحالي", project.selectedVersion().name);
        assertEquals(1, project.selectedVersion().files.size());
        assertEquals(legacyFile.id, project.selectedVersion().files.get(0).id);
        assertNotNull(project.secretVault);
        assertEquals("project-vault-project-alpha", project.secretVault.id);
        assertEquals("kept-encrypted-payload", project.secretVault.payload);

        JSONObject upgradedJson = migrated.toJson();
        assertEquals(3, upgradedJson.getInt("schemaVersion"));
        JSONObject upgradedProject = upgradedJson.getJSONArray("projects").getJSONObject(0);
        assertFalse(upgradedProject.has("files"));
        assertEquals(1, upgradedProject.getJSONArray("versions").length());
        WorkspaceData loadedAgain = WorkspaceData.fromJson(upgradedJson);
        assertFalse(loadedAgain.needsMigration);
        assertEquals(1, loadedAgain.projects.get(0).versions.size());
        assertEquals(1, loadedAgain.projects.get(0).selectedVersion().files.size());
        assertEquals(legacyFile.id, loadedAgain.projects.get(0).selectedVersion().files.get(0).id);
    }

    @Test public void versionsKeepSeparateFilesAndOneSharedProjectVault() throws Exception {
        Project project = new Project();
        project.id = "project-beta";
        project.name = "Beta";
        project.secretVault = new EncryptedVault("project-vault-project-beta");
        project.secretVault.salt = "salt";
        project.secretVault.payload = "encrypted";
        project.selectedVersion().name = "1.0";
        project.selectedVersion().files.add(attachment("22222222-2222-4222-8222-222222222222", "v1.zip", 10L));
        ProjectVersion next = project.addVersion("1.1");
        next.files.add(attachment("33333333-3333-4333-8333-333333333333", "patch.zip", 20L));

        Project restored = Project.fromJson(project.toJson());

        assertEquals(2, restored.versions.size());
        assertEquals("1.1", restored.selectedVersion().name);
        assertEquals(1, restored.versions.get(1).files.size());
        assertEquals("v1.zip", restored.versions.get(0).files.get(0).name);
        assertEquals("patch.zip", restored.versions.get(1).files.get(0).name);
        assertEquals("project-vault-project-beta", restored.secretVault.id);
        assertEquals("encrypted", restored.secretVault.payload);
    }

    private VaultAttachment attachment(String id, String name, long size) {
        VaultAttachment file = new VaultAttachment();
        file.id = id;
        file.name = name;
        file.sizeBytes = size;
        return file;
    }
}

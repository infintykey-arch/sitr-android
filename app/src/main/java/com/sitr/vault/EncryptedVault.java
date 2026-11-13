package com.sitr.vault;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.UUID;

final class EncryptedVault {
    String id = UUID.randomUUID().toString();
    String salt = "";
    String payload = "";

    EncryptedVault() {}

    EncryptedVault(String vaultId) {
        if (vaultId == null || vaultId.trim().isEmpty()) throw new IllegalArgumentException("Vault ID is required");
        id = vaultId;
    }

    boolean isInitialized() {
        return salt != null && !salt.isEmpty() && payload != null && !payload.isEmpty();
    }

    EncryptedVault copy() {
        EncryptedVault copy = new EncryptedVault(id);
        copy.salt = salt;
        copy.payload = payload;
        return copy;
    }

    JSONObject toJson() throws JSONException {
        JSONObject object = new JSONObject();
        object.put("id", id);
        object.put("salt", salt);
        object.put("payload", payload);
        return object;
    }

    static EncryptedVault fromJson(JSONObject object) {
        EncryptedVault vault = new EncryptedVault(object.optString("id", UUID.randomUUID().toString()));
        vault.salt = object.optString("salt", "");
        vault.payload = object.optString("payload", "");
        return vault;
    }
}

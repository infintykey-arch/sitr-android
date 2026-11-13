package com.sitr.vault;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.UUID;

final class VaultAttachment {
    String id = UUID.randomUUID().toString();
    String name = "";
    String mimeType = "application/octet-stream";
    long sizeBytes;

    JSONObject toJson() throws JSONException {
        JSONObject object = new JSONObject();
        object.put("id", id);
        object.put("name", name);
        object.put("mimeType", mimeType);
        object.put("sizeBytes", sizeBytes);
        return object;
    }

    static VaultAttachment fromJson(JSONObject object) {
        VaultAttachment attachment = new VaultAttachment();
        attachment.id = object.optString("id", UUID.randomUUID().toString());
        attachment.name = object.optString("name", "مرفق");
        attachment.mimeType = object.optString("mimeType", "application/octet-stream");
        attachment.sizeBytes = object.optLong("sizeBytes", 0L);
        return attachment;
    }
}

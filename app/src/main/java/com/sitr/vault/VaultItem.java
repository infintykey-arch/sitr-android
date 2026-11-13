package com.sitr.vault;

import org.json.JSONException;
import org.json.JSONArray;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

final class VaultItem {
    String id = UUID.randomUUID().toString();
    String title = "";
    String account = "";
    String secret = "";
    String note = "";
    List<VaultAttachment> attachments = new ArrayList<>();

    JSONObject toJson() throws JSONException {
        JSONObject o = new JSONObject();
        o.put("id", id);
        o.put("title", title);
        o.put("account", account);
        o.put("secret", secret);
        o.put("note", note);
        JSONArray attachmentArray = new JSONArray();
        for (VaultAttachment attachment : attachments) attachmentArray.put(attachment.toJson());
        o.put("attachments", attachmentArray);
        return o;
    }

    static VaultItem fromJson(JSONObject o) {
        VaultItem item = new VaultItem();
        item.id = o.optString("id", UUID.randomUUID().toString());
        item.title = o.optString("title", "");
        item.account = o.optString("account", "");
        item.secret = o.optString("secret", "");
        item.note = o.optString("note", "");
        JSONArray attachmentArray = o.optJSONArray("attachments");
        if (attachmentArray != null) {
            for (int i = 0; i < attachmentArray.length(); i++) {
                JSONObject attachmentObject = attachmentArray.optJSONObject(i);
                if (attachmentObject != null) item.attachments.add(VaultAttachment.fromJson(attachmentObject));
            }
        }
        return item;
    }
}

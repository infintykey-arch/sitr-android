package com.sitr.vault;

import java.util.Arrays;
import java.util.List;

import javax.crypto.spec.SecretKeySpec;

final class VaultSession {
    EncryptedVault vault;
    SecretKeySpec key;
    final List<VaultItem> items;

    VaultSession(EncryptedVault vault, SecretKeySpec key, List<VaultItem> items) {
        this.vault = vault;
        this.key = key;
        this.items = items;
    }

    void destroy() {
        if (key != null) {
            byte[] bytes = key.getEncoded();
            if (bytes != null) Arrays.fill(bytes, (byte) 0);
            key = null;
        }
        for (VaultItem item : items) {
            item.title = "";
            item.account = "";
            item.secret = "";
            item.note = "";
            if (item.attachments != null) item.attachments.clear();
        }
        items.clear();
        vault = null;
    }
}

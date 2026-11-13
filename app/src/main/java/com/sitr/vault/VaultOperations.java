package com.sitr.vault;

import java.util.List;
import java.util.Locale;

final class VaultOperations {
    private VaultOperations() {}

    static boolean hasDuplicateContent(List<VaultItem> items, String title, String secret, VaultItem except) {
        String normalizedTitle = title == null ? "" : title.trim().toLowerCase(Locale.ROOT);
        String normalizedSecret = secret == null ? "" : secret;
        for (VaultItem saved : items) {
            if (saved == except) continue;
            String savedTitle = saved.title == null ? "" : saved.title.trim().toLowerCase(Locale.ROOT);
            String savedSecret = saved.secret == null ? "" : saved.secret;
            if (normalizedTitle.equals(savedTitle) && normalizedSecret.equals(savedSecret)) return true;
        }
        return false;
    }

    static boolean addOne(List<VaultItem> items, VaultItem item) {
        if (items.contains(item)) return false;
        items.add(0, item);
        return true;
    }

    static int removeOne(List<VaultItem> items, VaultItem item) {
        int index = items.indexOf(item);
        if (index >= 0) items.remove(index);
        return index;
    }
}

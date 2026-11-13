package com.sitr.vault;

import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class VaultStoreBehaviorTest {
    private List<VaultItem> items;

    @Before public void setUp() {
        items = new ArrayList<>();
    }

    @Test public void oneAddSubmissionCreatesOneRecordOnly() {
        VaultItem item = item("GitHub", "same-secret", "ملاحظة");
        assertFalse(VaultOperations.hasDuplicateContent(items, item.title, item.secret, null));
        assertTrue(VaultOperations.addOne(items, item));
        assertFalse(VaultOperations.addOne(items, item));
        assertTrue(VaultOperations.hasDuplicateContent(items, item.title, item.secret, null));
        assertEquals("الإضافة الواحدة يجب أن تنتج سجلًا واحدًا", 1, items.size());
    }

    @Test public void deletingOneOfThreeMatchingRecordsRemovesOnlyThatRecord() {
        VaultItem first = item("Expo", "same-secret", "الأول");
        VaultItem selected = item("Expo", "same-secret", "المحدد للحذف");
        VaultItem third = item("Expo", "same-secret", "الثالث");
        items.add(first);
        items.add(selected);
        items.add(third);
        assertEquals(3, items.size());

        int removedIndex = VaultOperations.removeOne(items, selected);

        assertEquals(1, removedIndex);
        assertEquals("حذف سجل واحد من ثلاثة يجب أن يترك سجلين", 2, items.size());
        assertTrue(items.contains(first));
        assertFalse(items.contains(selected));
        assertTrue(items.contains(third));
        assertEquals("الثالث", items.get(1).note);
    }

    @Test public void exactDuplicateContentIsRejectedWithoutMergingSavedRows() {
        VaultItem original = item("Expo", "same-secret", "الأصل");
        VaultItem attempted = item("Expo", "same-secret", "محاولة ثانية");
        assertTrue(VaultOperations.addOne(items, original));
        assertTrue(VaultOperations.hasDuplicateContent(items, attempted.title, attempted.secret, null));
        assertEquals(1, items.size());

        VaultItem anotherSavedRow = item("Expo", "same-secret", "سجل موجود مستقل");
        items.add(anotherSavedRow);
        assertEquals("لا ينبغي دمج السجلات المحفوظة المتطابقة تلقائيًا", 2, items.size());
        assertEquals(0, VaultOperations.removeOne(items, original));
        assertEquals(1, items.size());
        assertTrue(items.contains(anotherSavedRow));
    }

    private VaultItem item(String title, String secret, String note) {
        VaultItem item = new VaultItem();
        item.title = title;
        item.secret = secret;
        item.note = note;
        return item;
    }
}

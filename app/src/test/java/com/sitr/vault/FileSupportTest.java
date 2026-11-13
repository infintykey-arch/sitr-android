package com.sitr.vault;

import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class FileSupportTest {
    @Test public void recognizesZipApkPdfWordAndSourceFiles() {
        assertTrue(FileSupport.isZip("release.zip", "application/octet-stream"));
        assertTrue(FileSupport.isApk("release.apk", null));
        assertTrue(FileSupport.isPdfOrWord("guide.pdf", null));
        assertTrue(FileSupport.isPdfOrWord("guide.docx", null));
        assertTrue(FileSupport.isEditableText("MainActivity.java", null));
        assertFalse(FileSupport.isEditableText("report.pdf", "application/pdf"));
    }

    @Test public void rejectsZipSlipAndAbsolutePaths() {
        assertNull(FileSupport.safeZipEntryName("../secret.txt"));
        assertNull(FileSupport.safeZipEntryName("folder/../../secret.txt"));
        assertNull(FileSupport.safeZipEntryName("/etc/passwd"));
        assertNull(FileSupport.safeZipEntryName("C:\\Windows\\win.ini"));
    }

    @Test public void normalizesSafeZipPathsAndDisambiguatesExportNames() {
        assertEquals("folder/sub/file.txt", FileSupport.safeZipEntryName("folder\\sub\\file.txt"));
        Set<String> names = new HashSet<>();
        assertEquals("file.txt", FileSupport.uniqueFlatZipName("folder/file.txt", names));
        assertEquals("file (2).txt", FileSupport.uniqueFlatZipName("elsewhere/file.txt", names));
    }
}

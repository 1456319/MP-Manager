package io.github.abdurazaaqmohammed.feature.apk.privacy;

import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.*;

public class ApkBundlePackerTest {

    private File createDummyApk(File dir, String filename) throws IOException {
        File apk = new File(dir, filename);
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(apk))) {
            zos.putNextEntry(new ZipEntry("AndroidManifest.xml"));
            zos.write(new byte[]{1, 2, 3, 4});
            zos.closeEntry();
        }
        return apk;
    }

    @Test
    public void testDiscoverCompanionSplits() throws Exception {
        File dir = Files.createTempDirectory("split_test").toFile();

        File base = createDummyApk(dir, "base.apk");
        File split1 = createDummyApk(dir, "split_config.arm64_v8a.apk");
        File split2 = createDummyApk(dir, "split_config.xxhdpi.apk");
        File split3 = createDummyApk(dir, "config.en.apk");
        File sanitized = createDummyApk(dir, "base_sanitized.apk");
        File otherFile = new File(dir, "readme.txt");
        assertTrue(otherFile.createNewFile());

        List<File> splits = ApkBundlePacker.discoverCompanionSplits(base);

        assertEquals("Should discover exactly 3 companion splits", 3, splits.size());
        assertTrue("Must contain split1", splits.contains(split1));
        assertTrue("Must contain split2", splits.contains(split2));
        assertTrue("Must contain split3", splits.contains(split3));
        assertFalse("Must NOT contain base", splits.contains(base));
        assertFalse("Must NOT contain sanitized output", splits.contains(sanitized));
        assertFalse("Must NOT contain text files", splits.contains(otherFile));
    }

    @Test
    public void testDiscoverCompanionSplitsFiltersUnrelatedApks() throws Exception {
        File dir = Files.createTempDirectory("split_filter_test").toFile();

        File base = createDummyApk(dir, "base.apk");
        File split1 = createDummyApk(dir, "split_config.arm64_v8a.apk");
        File split2 = createDummyApk(dir, "config.xxhdpi.apk");
        File unrelatedApp1 = createDummyApk(dir, "my_cool_game.apk");
        File unrelatedApp2 = createDummyApk(dir, "spotify_backup.apk");

        List<File> splits = ApkBundlePacker.discoverCompanionSplits(base);

        assertEquals("Only valid split filenames should be discovered", 2, splits.size());
        assertTrue(splits.contains(split1));
        assertTrue(splits.contains(split2));
        assertFalse(splits.contains(unrelatedApp1));
        assertFalse(splits.contains(unrelatedApp2));
        assertFalse(splits.contains(base));
    }

    @Test
    public void testVerifySignatureConsistencyRejectsMismatch() throws Exception {
        File dir = Files.createTempDirectory("sig_test").toFile();
        File apk1 = createDummyApk(dir, "apk1.apk");
        File apk2 = createDummyApk(dir, "apk2.apk");

        // Unsigned dummy APKs must fail verification consistency
        boolean consistent = ApkBundlePacker.verifySignatureConsistency(List.of(apk1, apk2));
        assertFalse("Unsigned dummy APKs must not be reported as consistent signed set", consistent);
    }
}

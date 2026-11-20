package io.github.abdurazaaqmohammed.feature.apk.privacy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.android.tools.smali.dexlib2.DexFileFactory;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.smali.Smali;
import com.android.tools.smali.smali.SmaliOptions;

import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Unit tests verifying Semantic Privacy Scanner, coverage metrics, and Invasiveness Risk Scoring.
 */
public class PrivacyScannerEngineTest {

    private static final String INVASIVE_APP_SMALI =
            """
            .class public Lcom/example/InvasiveApp;
            .super Landroid/app/Activity;
            .source "InvasiveApp.java"

            .method public constructor <init>()V
                .locals 1
                invoke-direct {p0}, Landroid/app/Activity;-><init>()V
                return-void
            .end method

            .method public snoopUser(Landroid/telephony/TelephonyManager;Landroid/content/ContentResolver;)V
                .locals 3
                invoke-virtual {p1}, Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;
                move-result-object v0
                const-string v1, "android_id"
                invoke-static {p2, v1}, Landroid/provider/Settings$Secure;->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;
                move-result-object v2
                const-string v1, "TAG"
                invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
                return-void
            .end method

            .method public checkEnvironment(Landroid/content/pm/PackageManager;Landroid/content/ContentResolver;)V
                .locals 2
                const/4 v0, 0x0
                invoke-virtual {p1, v0}, Landroid/content/pm/PackageManager;->getInstalledPackages(I)Ljava/util/List;
                move-result-object v1
                const-string v0, "adb_enabled"
                invoke-static {p2, v0}, Landroid/provider/Settings$Global;->getInt(Landroid/content/ContentResolver;Ljava/lang/String;)I
                return-void
            .end method
            """;

    private File assembleSmali(String smaliCode) throws Exception {
        File dir = Files.createTempDirectory("scanner_test").toFile();
        File pkg = new File(dir, "com/example");
        assertTrue(pkg.mkdirs());
        try (FileWriter w = new FileWriter(new File(pkg, "InvasiveApp.smali"))) {
            w.write(smaliCode);
        }
        File outDex = new File(dir, "classes.dex");
        SmaliOptions options = new SmaliOptions();
        options.outputDexFile = outDex.getPath();
        options.jobs = 1;
        options.apiLevel = 26;
        assertTrue(Smali.assemble(options, dir.getPath()));
        return outDex;
    }

    @Test
    public void testPrivacyScanningAndScoring() throws Exception {
        File dexFile = assembleSmali(INVASIVE_APP_SMALI);
        DexBackedDexFile dex = DexFileFactory.loadDexFile(dexFile, Opcodes.getDefault());

        PrivacyAuditReport report = PrivacyScannerEngine.scanClasses(dex.getClasses());

        assertNotNull(report);
        assertTrue("Overall score should be > 0, got: " + report.overallScore, report.overallScore > 0);
        assertTrue("Hardware score should be > 0, got: " + report.hardwareScore, report.hardwareScore > 0);
        assertTrue("Surveillance score should be > 0, got: " + report.surveillanceScore, report.surveillanceScore > 0);
        assertTrue("Log leak score should be > 0, got: " + report.logLeakScore, report.logLeakScore > 0);
        assertTrue(report.threats.size() >= 4);

        // Check categories present in report
        boolean foundHw = false;
        boolean foundSurv = false;
        boolean foundLog = false;

        for (DetectedThreat threat : report.threats) {
            assertEquals("[Non-Root]", threat.getRootBadge());
            assertFalse(threat.requiresRoot);
            if (threat.category == DetectedThreat.Category.HARDWARE_FINGERPRINT) foundHw = true;
            if (threat.category == DetectedThreat.Category.SURVEILLANCE) foundSurv = true;
            if (threat.category == DetectedThreat.Category.LOG_LEAK) foundLog = true;
        }

        assertTrue("Hardware fingerprint threat missing", foundHw);
        assertTrue("Surveillance threat missing", foundSurv);
        assertTrue("Log leak threat missing", foundLog);
    }

    @Test
    public void testStrictTrackerPrefixMatching() throws Exception {
        String unrelatedSmali = """
            .class public Lcom/example/studio/branching/Unrelated;
            .super Ljava/lang/Object;
            .source "Unrelated.java"

            .method public constructor <init>()V
                .locals 0
                invoke-direct {p0}, Ljava/lang/Object;-><init>()V
                return-void
            .end method
            """;
        File dexFile = assembleSmali(unrelatedSmali);
        DexBackedDexFile dex = DexFileFactory.loadDexFile(dexFile, Opcodes.getDefault());
        PrivacyAuditReport report = PrivacyScannerEngine.scanClasses(dex.getClasses());

        assertEquals("Substring match must not falsely trigger tracker threat", 0, report.threats.size());
        assertEquals(0, report.trackerScore);
    }

    @Test
    public void testTrackerScoreCalibration() {
        PrivacyAuditReport report = new PrivacyAuditReport();
        // 7 classes belonging to a single SDK must not saturate the subscore to 100
        for (int i = 0; i < 7; i++) {
            report.addThreat(new DetectedThreat(
                    DetectedThreat.Category.TRACKER_SDK,
                    "Third-Party Telemetry SDK: appsflyer",
                    "SDK description",
                    "Lcom/appsflyer/internal/Class" + i + ";",
                    "<class>",
                    DetectedThreat.ExcisionType.MANIFEST_STRIP,
                    false
            ));
        }
        report.computeScores();
        assertEquals("Single tracker SDK must produce calibrated score of 30, not 100", 30, report.trackerScore);

        // One hardware identifier alone must produce a noticeable score
        PrivacyAuditReport hwReport = new PrivacyAuditReport();
        hwReport.addThreat(new DetectedThreat(
                DetectedThreat.Category.HARDWARE_FINGERPRINT,
                "Telephony Identifier Read (getDeviceId)",
                "Queries IMEI",
                "Lcom/example/App;",
                "query",
                DetectedThreat.ExcisionType.BLANK_RETURN_STRING,
                false
        ));
        hwReport.computeScores();
        assertEquals(50, hwReport.hardwareScore);
        assertEquals(18, hwReport.overallScore);
    }

    @Test
    public void testStringRegisterInvalidation() throws Exception {
        String overwriteSmali = """
            .class public Lcom/example/RegOverwrite;
            .super Ljava/lang/Object;
            .source "RegOverwrite.java"

            .method public static check(Landroid/content/ContentResolver;Ljava/lang/String;)V
                .locals 2
                const-string v1, "adb_enabled"
                move-object v1, p1
                invoke-static {p0, v1}, Landroid/provider/Settings$Global;->getInt(Landroid/content/ContentResolver;Ljava/lang/String;)I
                return-void
            .end method
            """;
        File dexFile = assembleSmali(overwriteSmali);
        DexBackedDexFile dex = DexFileFactory.loadDexFile(dexFile, Opcodes.getDefault());
        PrivacyAuditReport report = PrivacyScannerEngine.scanClasses(dex.getClasses());

        // Since v1 was overwritten before invocation, it must not match "adb_enabled"
        assertEquals("Overwritten register must not match stale adb_enabled string", 0, report.threats.size());
    }

    @Test
    public void testCoverageMetricsAndResilience() throws Exception {
        File apkFile = File.createTempFile("coverage_test", ".apk");
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(apkFile))) {
            // 1. Valid DEX
            File dex1 = assembleSmali(INVASIVE_APP_SMALI);
            zos.putNextEntry(new ZipEntry("classes.dex"));
            zos.write(Files.readAllBytes(dex1.toPath()));
            zos.closeEntry();

            // 2. Corrupted DEX (garbage bytes)
            zos.putNextEntry(new ZipEntry("classes2.dex"));
            zos.write(new byte[]{0x64, 0x65, 0x78, 0x0a, 0x00, 0x00, 0x00, 0x00});
            zos.closeEntry();

            // 3. Native library with su probe
            zos.putNextEntry(new ZipEntry("lib/arm64-v8a/libtest.so"));
            zos.write("Some ELF content containing /system/bin/su for root probe".getBytes(StandardCharsets.ISO_8859_1));
            zos.closeEntry();

            // 4. AndroidManifest with declared permissions (including high-risk usage stats)
            String manifestXml = """
                <?xml version="1.0" encoding="utf-8"?>
                <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.test">
                    <uses-permission android:name="android.permission.INTERNET"/>
                    <uses-permission android:name="android.permission.PACKAGE_USAGE_STATS"/>
                </manifest>
                """;
            zos.putNextEntry(new ZipEntry("AndroidManifest.xml"));
            zos.write(manifestXml.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }

        PrivacyAuditReport report = PrivacyScannerEngine.scanApk(apkFile);

        assertNotNull(report);
        assertEquals(2, report.totalDexFilesFound);
        assertEquals(1, report.totalDexFilesScanned);
        assertEquals(1, report.totalDexFilesFailed);
        assertEquals(1, report.totalNativeLibsFound);
        assertEquals(1, report.totalNativeLibsScanned);
        assertEquals(0, report.totalNativeLibsFailed);
        assertFalse(report.scanWarnings.isEmpty());
        assertTrue(report.scanWarnings.get(0).contains("classes2.dex"));

        // Verify Manifest permissions extracted
        assertEquals(2, report.declaredPermissions.size());
        assertTrue(report.declaredPermissions.contains("android.permission.INTERNET"));
        assertTrue(report.declaredPermissions.contains("android.permission.PACKAGE_USAGE_STATS"));
        assertEquals(1, report.highRiskPermissions.size());
        assertTrue(report.highRiskPermissions.contains("android.permission.PACKAGE_USAGE_STATS"));

        // Verify high-risk permission threat recorded
        boolean foundPermThreat = false;
        for (DetectedThreat threat : report.threats) {
            if (threat.title.contains("PACKAGE_USAGE_STATS")) {
                foundPermThreat = true;
                break;
            }
        }
        assertTrue("High-risk permission threat must be added to threats list", foundPermThreat);

        apkFile.delete();
    }
}

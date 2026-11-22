package io.github.abdurazaaqmohammed.feature.apk.privacy;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.reandroid.apk.APKLogger;

import org.junit.Test;

import java.io.File;

/**
 * Empirical test running the 'Safe' (Standard) version of the Sterilizer
 * against candidate cashback applications extracted from the user's device.
 */
public class CashbackSanitizerEmpiricalTest {

    private static final File CASHBACK_BASE_DIR = new File("/home/deck/.gemini/antigravity/scratch/cashback_apps");

    private static final APKLogger LOGGER = new APKLogger() {
        @Override
        public void logMessage(String message) {
            System.out.println("[STERILIZER] " + message);
        }

        @Override
        public void logError(String message, Throwable tr) {
            System.err.println("[STERILIZER-ERR] " + message);
            if (tr != null) tr.printStackTrace();
        }

        @Override
        public void logVerbose(String message) {
            // suppress verbose
        }
    };

    private void runSterilizerOnApp(String packageName) throws Exception {
        File appDir = new File(CASHBACK_BASE_DIR, packageName);
        File baseApk = new File(appDir, "base.apk");
        org.junit.Assume.assumeTrue("Base APK must exist at " + baseApk, baseApk.exists());

        File outApk = new File(appDir, "base_sanitized_standard.apk");
        if (outApk.exists()) outApk.delete();

        System.out.println("\n=======================================================");
        System.out.println(">>> TESTING APP: " + packageName + " (" + (baseApk.length() / 1024 / 1024) + " MB)");
        System.out.println("=======================================================");

        long start = System.currentTimeMillis();
        PrivacyOptions safeOptions = PrivacyOptions.standard();

        PrivacyAuditReport report = PrivacyBytecodeEngine.sanitizeApkWithAudit(
                baseApk, outApk, safeOptions, LOGGER
        );

        long elapsed = System.currentTimeMillis() - start;

        assertNotNull("Report must not be null", report);
        PrivacyStats stats = report.sanitizationStats;
        assertNotNull("Stats must not be null", stats);

        System.out.println("--- Results for " + packageName + " in " + elapsed + " ms ---");
        System.out.println("Overall Status: " + report.overallSanitizationStatus);
        System.out.println("Telemetry Module: " + report.telemetryModuleResult.status + " (" + report.telemetryModuleResult.mutationsApplied + " mutations)");
        System.out.println("AI Module: " + report.aiModuleResult.status + " (" + report.aiModuleResult.mutationsApplied + " mutations)");
        System.out.println("Classes Modified: " + stats.classesModified);
        System.out.println("Total Mutations: " + stats.totalMutations());
        System.out.println("  - Log Calls Stripped: " + stats.logCallsStripped);
        System.out.println("  - Telephony IDs Blanked: " + stats.telephonyGettersBlanked);
        System.out.println("  - Ad IDs Neutralized: " + stats.adIdsNeutralized);
        System.out.println("  - Dev Mode Masked: " + stats.devModeChecksMasked);
        System.out.println("  - Telemetry Domains Sinkholed: " + stats.telemetryDomainsSinkholed);
        System.out.println("  - Background Workers Neutralized: " + stats.backgroundWorkersNeutralized);
        System.out.println("  - Hardware Identifiers Blanked: " + stats.hardwareIdentifiersBlanked);
        System.out.println("  - Periodic Work Suppressed: " + stats.periodicWorkEnqueueSuppressed);
        System.out.println("  - Dead Code Skipped: " + stats.deadCodeSkipped);
        System.out.println("Sanitized APK Size: " + (outApk.exists() ? (outApk.length() / 1024 / 1024) + " MB" : "0 MB"));
        assertTrue("Sanitized APK must exist and be non-empty", outApk.exists() && outApk.length() > 1024 * 1024);
    }

    @Test
    public void testUpsideConsumer() throws Exception {
        runSterilizerOnApp("com.upside.consumer.android");
    }

    @Test
    public void testAttainBoomerang() throws Exception {
        runSterilizerOnApp("io.attaindata.boomerang");
    }

    @Test
    public void testReceiptHog() throws Exception {
        runSterilizerOnApp("com.infoscout.receipthog");
    }

    @Test
    public void testJoko() throws Exception {
        runSterilizerOnApp("io.wylr.joko");
    }
}

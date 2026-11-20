package io.github.abdurazaaqmohammed.feature.apk.privacy;

import com.reandroid.apk.ApkModule;
import com.reandroid.archive.InputSource;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * Audits compiled native ELF (.so) binaries inside APK lib/ directories for
 * low-level surveillance, /proc snooping, and root detection strings.
 * Flags threats with [Requires Root] where static DEX patching cannot safely reach.
 */
public final class NativeLibAuditor {

    private NativeLibAuditor() {}

    private static final List<String> ROOT_SURVEILLANCE_STRINGS = Arrays.asList(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/data/local/tmp/su",
            "/proc/mounts",
            "/proc/net/arp",
            "/proc/self/maps",
            "/proc/self/status",
            "ro.debuggable",
            "service.adb.root",
            "ro.secure"
    );

    /**
     * Audits all native shared libraries inside an APK and appends detected threats to the report.
     */
    public static void auditNativeLibs(ApkModule module, PrivacyAuditReport report) {
        if (module == null || report == null) return;

        for (InputSource source : module.getInputSources()) {
            String name = source.getName();
            if (!name.startsWith("lib/") || !name.endsWith(".so")) continue;

            report.totalNativeLibsFound++;
            try (InputStream is = source.openStream()) {
                byte[] bytes = readAll(is);
                report.totalNativeLibsScanned++;
                String elfContent = new String(bytes, StandardCharsets.ISO_8859_1);

                for (String probe : ROOT_SURVEILLANCE_STRINGS) {
                    if (elfContent.contains(probe)) {
                        report.addThreat(new DetectedThreat(
                                DetectedThreat.Category.SURVEILLANCE,
                                "Native Binary Root / Environment Probe (" + probe + ")",
                                "Compiled native ELF library probes Linux system paths or root binaries via C/C++.",
                                name,
                                "<native ELF>",
                                DetectedThreat.ExcisionType.NOP_INVOKE,
                                true // REQUIRES ROOT: Native checks cannot be bypassed statically without risking ABI crashes
                        ));
                    }
                }
            } catch (Throwable t) {
                report.totalNativeLibsFailed++;
                report.scanWarnings.add("Could not read native library " + name + ": " + t.getMessage());
            }
        }
    }

    private static final int MAX_ELF_AUDIT_BYTES = 16 * 1024 * 1024; // 16 MB max scan per native binary

    private static byte[] readAll(InputStream is) throws Exception {
        try (is; ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[65536];
            int n;
            int total = 0;
            while ((n = is.read(buf)) != -1) {
                bos.write(buf, 0, n);
                total += n;
                if (total >= MAX_ELF_AUDIT_BYTES) break;
            }
            return bos.toByteArray();
        }
    }
}

package io.github.abdurazaaqmohammed.feature.apk.privacy;

import com.android.apksig.ApkVerifier;
import com.reandroid.apk.ApkModule;
import io.github.abdurazaaqmohammed.feature.apk.SignWrapper;
import org.apache.commons.io.FilenameUtils;

import java.io.File;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

/**
 * Utility for discovering companion split APKs in an application package,
 * verifying signature consistency across all APK splits in a set,
 * and batch co-signing companion splits to prevent Android PackageManager
 * signature mismatch installation failures.
 */
public final class ApkBundlePacker {

    private ApkBundlePacker() {
        // Utility class
    }

    /**
     * Extracts the Android package name from an APK using ReAndroid ApkModule.
     * Returns null if unreadable.
     */
    public static String getApkPackageName(File apk) {
        if (apk == null || !apk.exists() || !apk.isFile()) {
            return null;
        }
        try (ApkModule module = ApkModule.loadApkFile(apk)) {
            module.setLoadDefaultFramework(false);
            return module.getPackageName();
        } catch (Exception ignored) {
            return null;
        }
    }

    /**
     * Checks if a filename matches standard Android split APK conventions:
     * - starts with "split_" (e.g. split_config.arm64_v8a.apk)
     * - starts with "config." (e.g. config.en.apk)
     * - contains ".config."
     * - ends with ".split.apk"
     */
    public static boolean isSplitFilename(String filename) {
        if (filename == null) return false;
        String lower = filename.toLowerCase();
        return lower.startsWith("split_")
                || lower.startsWith("config.")
                || lower.contains(".config.")
                || lower.endsWith(".split.apk");
    }

    /**
     * Discovers companion split APKs associated with a base APK in the same directory.
     * Filters candidate APKs strictly by:
     * 1. Must be a valid file ending with .apk (excluding base APK, sanitized APKs, and .tmp).
     * 2. Must match split naming convention OR share the identical package name.
     * 3. If base APK package name is resolved, candidate split package name must match.
     *
     * @param baseApk The base APK file
     * @return List of companion split APK files, or empty list if none found
     */
    public static List<File> discoverCompanionSplits(File baseApk) {
        if (baseApk == null || !baseApk.exists()) {
            return Collections.emptyList();
        }
        File parentDir = baseApk.getParentFile();
        if (parentDir == null || !parentDir.isDirectory()) {
            return Collections.emptyList();
        }

        File[] files = parentDir.listFiles();
        if (files == null || files.length == 0) {
            return Collections.emptyList();
        }

        String basePkg = getApkPackageName(baseApk);

        List<File> splits = new ArrayList<>();
        for (File f : files) {
            if (!f.isFile()) {
                continue;
            }
            String name = f.getName();
            if (!name.endsWith(".apk")) {
                continue;
            }
            if (f.equals(baseApk)) {
                continue;
            }
            if (name.contains("_sanitized")) {
                continue;
            }
            if (name.endsWith(".tmp") || name.endsWith(".idsig")) {
                continue;
            }

            boolean matchesSplitName = isSplitFilename(name);
            String candidatePkg = getApkPackageName(f);

            if (basePkg != null && candidatePkg != null) {
                // If both package names are parsed, they MUST match
                if (!basePkg.equals(candidatePkg)) {
                    continue;
                }
            } else if (!matchesSplitName) {
                // If package name could not be parsed, require standard split naming to prevent matching unrelated apps
                continue;
            }

            splits.add(f);
        }
        return splits;
    }

    /**
     * Verifies that all APKs in the list are validly signed and share identical
     * signing certificates (comparing all certificates and counts across each APK).
     *
     * @param apks List of APK files to verify
     * @return true if all APKs are validly signed with identical signer certificates, false otherwise
     */
    public static boolean verifySignatureConsistency(List<File> apks) {
        if (apks == null || apks.isEmpty()) {
            return false;
        }

        List<byte[]> referenceCerts = null;

        for (File apk : apks) {
            if (apk == null || !apk.exists() || !apk.isFile()) {
                return false;
            }

            try {
                ApkVerifier.Builder builder = new ApkVerifier.Builder(apk);
                ApkVerifier.Result result = builder.build().verify();
                if (!result.isVerified()) {
                    return false;
                }

                List<X509Certificate> certs = result.getSignerCertificates();
                if (certs == null || certs.isEmpty()) {
                    return false;
                }

                List<byte[]> currentCerts = new ArrayList<>(certs.size());
                for (X509Certificate c : certs) {
                    currentCerts.add(c.getEncoded());
                }

                if (referenceCerts == null) {
                    referenceCerts = currentCerts;
                } else {
                    if (referenceCerts.size() != currentCerts.size()) {
                        return false;
                    }
                    for (int i = 0; i < referenceCerts.size(); i++) {
                        if (!Arrays.equals(referenceCerts.get(i), currentCerts.get(i))) {
                            return false;
                        }
                    }
                }
            } catch (Exception e) {
                return false;
            }
        }

        return referenceCerts != null;
    }

    public static List<File> coSignSplitSet(File baseApk, List<File> splits, File outDir, SignWrapper signer) throws Exception {
        return coSignSplitSet(baseApk, splits, outDir, signer, null);
    }

    /**
     * Co-signs a base APK and its companion splits into an output directory using the same signer.
     * Prevents destructive in-place overwrite:
     * - If outDir is the same directory as the source APK, output files are given a non-colliding
     *   "_sanitized.apk" suffix so the original splits are preserved.
     * - If outDir is a separate destination directory, canonical split filenames are written.
     *
     * @param baseApk The base APK file (can be raw or sanitized)
     * @param splits Companion split APKs to co-sign
     * @param outDir Directory where signed APKs should be written
     * @param signer SignWrapper configured with signing keys
     * @param logger Optional consumer for log messages
     * @return List of signed APK files in outDir
     * @throws Exception if signing fails or I/O error occurs
     */
    public static List<File> coSignSplitSet(File baseApk, List<File> splits, File outDir, SignWrapper signer, Consumer<String> logger) throws Exception {
        if (!outDir.exists() && !outDir.mkdirs()) {
            throw new IOException("Failed to create output directory: " + outDir.getAbsolutePath());
        }

        List<File> signedOutputs = new ArrayList<>();

        if (baseApk != null && baseApk.exists()) {
            File outBase = resolveNonDestructiveOutput(baseApk, outDir);
            if (logger != null) {
                logger.accept("Signing base APK: " + outBase.getName());
            }
            signer.signApk(baseApk, outBase);
            signedOutputs.add(outBase);
        }

        if (splits != null) {
            for (File split : splits) {
                if (split == null || !split.exists()) {
                    continue;
                }
                File outSplit = resolveNonDestructiveOutput(split, outDir);
                if (logger != null) {
                    logger.accept("Signing companion split: " + outSplit.getName());
                }
                signer.signApk(split, outSplit);
                signedOutputs.add(outSplit);
            }
        }

        return signedOutputs;
    }

    private static File resolveNonDestructiveOutput(File sourceApk, File outDir) {
        if (outDir.equals(sourceApk.getParentFile())) {
            // Same directory: if already contains _sanitized, safe to reuse or overwrite
            String name = sourceApk.getName();
            if (name.contains("_sanitized")) {
                return sourceApk;
            }
            String base = FilenameUtils.getBaseName(name);
            return new File(outDir, base + "_sanitized.apk");
        } else {
            // Distinct directory: keep original filename
            return new File(outDir, sourceApk.getName());
        }
    }
}

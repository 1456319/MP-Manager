package io.github.abdurazaaqmohammed.feature.apk.privacy;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Audit report produced by PrivacyScannerEngine containing threat taxonomy and risk scores.
 */
public class PrivacyAuditReport implements Serializable {

    public enum RiskLevel {
        LOW,
        MODERATE,
        HIGH,
        CRITICAL
    }

    public int overallScore = 0; // 0 to 100
    public int hardwareScore = 0;
    public int surveillanceScore = 0;
    public int trackerScore = 0;
    public int logLeakScore = 0;

    public int totalClassesScanned = 0;
    public int invasiveClassesCount = 0;

    public int totalDexFilesFound = 0;
    public int totalDexFilesScanned = 0;
    public int totalDexFilesFailed = 0;

    public int totalNativeLibsFound = 0;
    public int totalNativeLibsScanned = 0;
    public int totalNativeLibsFailed = 0;

    public final List<String> declaredPermissions = new ArrayList<>();
    public final List<String> highRiskPermissions = new ArrayList<>();
    public final List<String> scanWarnings = new ArrayList<>();

    public final List<DetectedThreat> threats = new ArrayList<>();

    // ==========================================
    // Multi-DEX Sanitization & Audit Results
    // ==========================================
    public ModuleAuditResult telemetryModuleResult = new ModuleAuditResult("Module A: Telemetry", ModuleAuditResult.Status.NOT_DETECTED);
    public ModuleAuditResult aiModuleResult = new ModuleAuditResult("Module B: AI & Assistants", ModuleAuditResult.Status.NOT_DETECTED);
    public PrivacyStats sanitizationStats = new PrivacyStats();
    public ModuleAuditResult.Status overallSanitizationStatus = ModuleAuditResult.Status.NOT_DETECTED;

    public boolean isSanitizationSuccessful() {
        return overallSanitizationStatus == ModuleAuditResult.Status.SUCCESS;
    }

    public ModuleAuditResult.Status getOverallSanitizationStatus() {
        return overallSanitizationStatus;
    }

    public PrivacyStats getSanitizationStats() {
        return sanitizationStats;
    }

    public ModuleAuditResult getTelemetryModuleResult() {
        return telemetryModuleResult;
    }

    public ModuleAuditResult getAiModuleResult() {
        return aiModuleResult;
    }

    public RiskLevel getRiskLevel() {
        if (overallScore >= 75) return RiskLevel.CRITICAL;
        if (overallScore >= 50) return RiskLevel.HIGH;
        if (overallScore >= 25) return RiskLevel.MODERATE;
        return RiskLevel.LOW;
    }

    public void addThreat(DetectedThreat threat) {
        for (DetectedThreat existing : threats) {
            if (existing.category == threat.category
                    && existing.targetClass.equals(threat.targetClass)
                    && existing.targetMethod.equals(threat.targetMethod)
                    && existing.title.equals(threat.title)) {
                existing.occurrences += threat.occurrences;
                return;
            }
        }
        threats.add(threat);
    }

    public void computeScores() {
        int hwCount = 0;
        int survCount = 0;
        int logCount = 0;
        Set<String> distinctTrackers = new HashSet<>();

        for (DetectedThreat t : threats) {
            switch (t.category) {
                case HARDWARE_FINGERPRINT -> hwCount += t.occurrences;
                case SURVEILLANCE -> survCount += t.occurrences;
                case TRACKER_SDK -> distinctTrackers.add(t.title);
                case LOG_LEAK -> logCount += t.occurrences;
            }
        }

        // Hardware Fingerprinting: Base 35 points for any hardware identifier query (IMEI, Serial, MAC, Android ID),
        // plus 15 per additional occurrence, bounded at 100.
        hardwareScore = (hwCount == 0) ? 0 : Math.min(100, 35 + (hwCount * 15));

        // Trackers: Calibrated by distinct tracker SDK architectures, avoiding saturation by class counts of 1 SDK.
        // 1 tracker SDK = 30, 2 = 55, 3 = 75, 4+ = 100.
        int trackerCount = distinctTrackers.size();
        trackerScore = switch (trackerCount) {
            case 0 -> 0;
            case 1 -> 30;
            case 2 -> 55;
            case 3 -> 75;
            default -> 100;
        };

        // Surveillance & Probes: Base 30 for any probe / invasive permission, plus 15 per occurrence up to 100.
        surveillanceScore = (survCount == 0) ? 0 : Math.min(100, 30 + (survCount * 15));

        // Diagnostic / Debug logging surface: Logarithmically scaled exposure.
        // Common log calls (e.g. 100) produce ~70 score rather than linear inflation.
        logLeakScore = (logCount == 0) ? 0 : (int) Math.min(100, Math.round(Math.log10(logCount + 1) * 35));

        // Factor in high-risk permissions if declared in manifest
        if (!highRiskPermissions.isEmpty()) {
            surveillanceScore = Math.min(100, surveillanceScore + (highRiskPermissions.size() * 15));
        }

        // Weighted overall score
        overallScore = (int) Math.round(
                (hardwareScore * 0.35) +
                (trackerScore * 0.30) +
                (surveillanceScore * 0.25) +
                (logLeakScore * 0.10)
        );
    }
}

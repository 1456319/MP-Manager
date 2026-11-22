package io.github.abdurazaaqmohammed.feature.apk.privacy;

import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.RelativeSizeSpan;
import android.text.style.StyleSpan;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.RadioGroup;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.preference.PreferenceManager;

import com.google.android.material.checkbox.MaterialCheckBox;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.radiobutton.MaterialRadioButton;
import com.reandroid.apk.APKLogger;

import org.apache.commons.io.FilenameUtils;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import io.github.abdurazaaqmohammed.MPManager.R;
import io.github.abdurazaaqmohammed.feature.apk.SignWrapper;
import io.github.abdurazaaqmohammed.ui.main.MainActivity;
import io.github.abdurazaaqmohammed.util.io.FileUtils;
import io.github.abdurazaaqmohammed.util.io.ProgressManager;
import io.github.abdurazaaqmohammed.util.misc.ErrorUtil;
import io.github.codehasan.colorpicker.extensions.Extensions;

/**
 * Interactive dialog displaying the Privacy & Invasiveness Audit report,
 * threat taxonomy, root requirement badges, and surgical sanitization pipeline.
 */
public final class PrivacyAuditDialog {

    private PrivacyAuditDialog() {}

    public static void showForApk(MainActivity context, File apkFile, String fileName) {
        if (apkFile == null || !apkFile.isFile()) return;

        ProgressManager pm = new ProgressManager(context, true).show();
        pm.setText("Auditing APK privacy...");

        new Thread(() -> {
            try {
                PrivacyAuditReport report = PrivacyScannerEngine.scanApk(apkFile);
                context.runOnUiThread(() -> {
                    pm.dismiss();
                    displayDialog(context, apkFile, report);
                });
            } catch (Exception e) {
                context.runOnUiThread(() -> {
                    pm.dismiss();
                    new ErrorUtil(context).showError(e);
                });
            }
        }).start();
    }

    private static void displayDialog(MainActivity context, File apkFile, PrivacyAuditReport report) {
        int pad = Extensions.dp2px(context, 16);
        int padSmall = Extensions.dp2px(context, 8);

        LinearLayout root = new LinearLayout(context);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, padSmall, pad, padSmall);

        // Header: Risk Score banner
        LinearLayout scoreBox = new LinearLayout(context);
        scoreBox.setOrientation(LinearLayout.VERTICAL);
        scoreBox.setPadding(padSmall, padSmall, padSmall, padSmall);

        int riskColor = switch (report.getRiskLevel()) {
            case CRITICAL -> Color.parseColor("#D32F2F"); // Red
            case HIGH -> Color.parseColor("#F57C00");     // Orange
            case MODERATE -> Color.parseColor("#FBC02D"); // Yellow
            case LOW -> Color.parseColor("#388E3C");      // Green
        };

        TextView scoreTitle = new TextView(context);
        scoreTitle.setText(String.format("Invasiveness Risk Score: %d/100 (%s)",
                report.overallScore, report.getRiskLevel().name()));
        scoreTitle.setTextSize(17);
        scoreTitle.setTypeface(Typeface.DEFAULT_BOLD);
        scoreTitle.setTextColor(riskColor);
        scoreBox.addView(scoreTitle);

        TextView statsSummary = new TextView(context);
        statsSummary.setText(String.format(
                "• %s\n• %s\n• %s\n• %s",
                context.getString(R.string.privacy_hw_score, report.hardwareScore),
                context.getString(R.string.privacy_track_score, report.trackerScore),
                context.getString(R.string.privacy_surv_score, report.surveillanceScore),
                context.getString(R.string.privacy_log_score, report.logLeakScore)
        ));
        statsSummary.setTextSize(13);
        statsSummary.setPadding(0, padSmall, 0, 0);
        scoreBox.addView(statsSummary);

        TextView coverageSummary = new TextView(context);
        coverageSummary.setText(String.format(
                context.getString(R.string.privacy_scan_coverage),
                report.totalDexFilesFound,
                report.totalDexFilesScanned,
                report.totalDexFilesFailed,
                report.totalClassesScanned,
                report.totalNativeLibsScanned,
                report.declaredPermissions.size()
        ));
        coverageSummary.setTextSize(12);
        coverageSummary.setTextColor(Color.parseColor("#757575"));
        coverageSummary.setPadding(0, padSmall, 0, 0);
        scoreBox.addView(coverageSummary);

        if (!report.scanWarnings.isEmpty()) {
            TextView warningsText = new TextView(context);
            warningsText.setText(String.format("⚠️ %d scan warning(s) during analysis (some files skipped or unreadable)", report.scanWarnings.size()));
            warningsText.setTextSize(12);
            warningsText.setTextColor(Color.parseColor("#D32F2F"));
            warningsText.setPadding(0, padSmall / 2, 0, 0);
            scoreBox.addView(warningsText);
        }

        root.addView(scoreBox);
        root.addView(createDivider(context));

        if (report.threats.isEmpty()) {
            TextView cleanMsg = new TextView(context);
            cleanMsg.setText(context.getString(R.string.privacy_clean_app_summary));
            cleanMsg.setTextSize(13);
            cleanMsg.setTextColor(Color.parseColor("#388E3C"));
            cleanMsg.setPadding(0, padSmall, 0, padSmall);
            root.addView(cleanMsg);
        } else {
            // Threats Header
            TextView threatsHeader = new TextView(context);
            threatsHeader.setText(String.format("Detected Threats & Invasiveness Capabilities (%d):", report.threats.size()));
            threatsHeader.setTextSize(14);
            threatsHeader.setTypeface(Typeface.DEFAULT_BOLD);
            threatsHeader.setPadding(0, padSmall, 0, padSmall);
            root.addView(threatsHeader);

            // Threat Items List
            for (DetectedThreat threat : report.threats) {
                LinearLayout itemRow = new LinearLayout(context);
                itemRow.setOrientation(LinearLayout.VERTICAL);
                itemRow.setPadding(0, padSmall / 2, 0, padSmall / 2);

                TextView itemTitle = new TextView(context);
                itemTitle.setText(String.format("• %s %s", threat.getRootBadge(), threat.title));
                itemTitle.setTextSize(13);
                itemTitle.setTypeface(Typeface.DEFAULT_BOLD);
                itemRow.addView(itemTitle);

                TextView itemDesc = new TextView(context);
                itemDesc.setText(String.format("%s (%d occurrences)", threat.description, threat.occurrences));
                itemDesc.setTextSize(12);
                itemDesc.setTextColor(Color.parseColor("#757575"));
                itemRow.addView(itemDesc);

                root.addView(itemRow);
            }
        }

        root.addView(createDivider(context));

        // Rewrite Held Notice
        TextView rewriteNotice = new TextView(context);
        rewriteNotice.setText(context.getString(R.string.privacy_rewrite_held_notice));
        rewriteNotice.setTextSize(12);
        rewriteNotice.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.ITALIC));
        rewriteNotice.setTextColor(Color.parseColor("#757575"));
        rewriteNotice.setPadding(0, padSmall, 0, padSmall);
        root.addView(rewriteNotice);

        // ScrollView container
        int maxHeight = (int) (context.getResources().getDisplayMetrics().heightPixels * 0.70);
        ScrollView scroller = new ScrollView(context);
        scroller.addView(root, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        new MaterialAlertDialogBuilder(context)
                .setTitle(R.string.privacy_audit_title)
                .setView(scroller)
                .setPositiveButton(android.R.string.ok, null)
                .show();
    }

    // Held pending granular per-target mutation control
    @SuppressWarnings("unused")
    private static void sanitizeAndSave(MainActivity context, File apkFile, PrivacyAuditReport report, boolean doSign, SanitizationMode selectedMode) {
        PrivacyOptions options = (selectedMode == SanitizationMode.AGGRESSIVE)
                ? PrivacyOptions.aggressive()
                : PrivacyOptions.standard();

        if (!isAnySelected(report.threats, DetectedThreat.Category.LOG_LEAK)) {
            options.stripLogging = false;
        }
        if (!isAnySelected(report.threats, DetectedThreat.Category.HARDWARE_FINGERPRINT)) {
            options.emptyTelephonyIds = false;
            options.neutralizeAdIds = false;
            options.blankAndroidId = false;
            options.blankHardwareSerial = false;
            options.blankWifiMac = false;
        }
        if (!isAnySelected(report.threats, DetectedThreat.Category.SURVEILLANCE)) {
            options.maskDeveloperMode = false;
        }
        if (!isAnySelected(report.threats, DetectedThreat.Category.TRACKER_SDK)) {
            options.sinkholeTelemetryDomains = false;
            options.neutralizeBackgroundWorkers = false;
        }

        File outFile = FileUtils.getUnusedFile(new File(apkFile.getParentFile(),
                FilenameUtils.getBaseName(apkFile.getName()) + "_sanitized.apk"));

        SignWrapper[] wrapper = new SignWrapper[1];

        Runnable doSanitize = () -> {
            ProgressManager pm = new ProgressManager(context, true).show();
            APKLogger logger = pm.getLogger();
            new Thread(() -> {
                try {
                    pm.setText("Sanitizing DEX bytecode...");
                    MutationPlan mutationPlan = MutationPlan.fromThreats(report.threats, options);
                    PrivacyAuditReport auditResult = PrivacyBytecodeEngine.sanitizeApkWithAudit(apkFile, outFile, options, null, mutationPlan, logger);
                    PrivacyStats stats = (auditResult != null && auditResult.getSanitizationStats() != null)
                            ? auditResult.getSanitizationStats()
                            : new PrivacyStats();

                    if (stats.totalMutations() == 0) {
                        pm.dismiss();
                        context.runOnUiThread(() -> {
                            Extensions.showMessage(context, context.getString(R.string.privacy_no_mutations_applied));
                            context.refreshAllPanes();
                        });
                        return;
                    }

                    if (doSign && wrapper[0] != null) {
                        List<File> splits = ApkBundlePacker.discoverCompanionSplits(apkFile);
                        if (!splits.isEmpty()) {
                            List<File> allInputs = new ArrayList<>();
                            allInputs.add(apkFile);
                            allInputs.addAll(splits);
                            boolean consistent = ApkBundlePacker.verifySignatureConsistency(allInputs);
                            if (consistent) {
                                pm.setText("Co-signing base and companion splits...");
                                List<File> signedSplits = ApkBundlePacker.coSignSplitSet(outFile, splits, outFile.getParentFile(), wrapper[0], logger != null ? logger::logMessage : null);
                                if (!ApkBundlePacker.verifySignatureConsistency(signedSplits) && logger != null) {
                                    logger.logMessage("Warning: Co-signed split bundle verification mismatch");
                                }
                            } else {
                                if (logger != null) {
                                    logger.logMessage("Companion splits signature mismatch or unsigned; signing base APK only");
                                }
                                pm.setText("Signing sanitized APK...");
                                wrapper[0].signApk(outFile);
                            }
                        } else {
                            pm.setText("Signing sanitized APK...");
                            wrapper[0].signApk(outFile);
                        }
                    }

                    pm.dismiss();
                    context.runOnUiThread(() -> {
                        Extensions.showMessage(context, context.getString(
                                R.string.privacy_done, stats.totalMutations()));
                        context.refreshAllPanes();
                    });
                } catch (Exception e) {
                    pm.dismiss();
                    context.runOnUiThread(() -> new ErrorUtil(context).showError(e));
                }
            }).start();
        };

        if (doSign) {
            SignWrapper.requireAuth(context, sw -> {
                wrapper[0] = sw;
                doSanitize.run();
            });
        } else {
            doSanitize.run();
        }
    }

    private static CharSequence createModeSpan(String title, String desc) {
        SpannableStringBuilder sb = new SpannableStringBuilder();
        sb.append(title);
        sb.setSpan(new StyleSpan(Typeface.BOLD), 0, title.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        sb.append("\n");
        int descStart = sb.length();
        sb.append(desc);
        sb.setSpan(new RelativeSizeSpan(0.85f), descStart, sb.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        return sb;
    }

    private static boolean isAnySelected(List<DetectedThreat> threats, DetectedThreat.Category category) {
        for (DetectedThreat t : threats) {
            if (t.category == category && t.selectedForExcision) return true;
        }
        return false;
    }

    private static View createDivider(MainActivity context) {
        View v = new View(context);
        v.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, Extensions.dp2px(context, 1)));
        v.setBackgroundColor(Color.parseColor("#33888888"));
        int m = Extensions.dp2px(context, 8);
        ((LinearLayout.LayoutParams) v.getLayoutParams()).setMargins(0, m, 0, m);
        return v;
    }
}

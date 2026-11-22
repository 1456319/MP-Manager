package io.github.abdurazaaqmohammed.feature.apk.privacy;

import java.io.Serializable;
import java.util.*;

/**
 * Immutable targeted mutation plan that maps specific classes and methods
 * to targeted privacy excisions.
 * Prevents wholesale APK mutation and ensures only user-approved findings are modified.
 */
public final class MutationPlan implements Serializable {
    private static final long serialVersionUID = 1L;

    public enum MutationAction {
        STRIP_LOG,
        NEUTRALIZE_AD_ID,
        BLANK_ANDROID_ID,
        BLANK_TELEPHONY,
        MASK_DEV_MODE,
        SINKHOLE_DOMAIN,
        NEUTRALIZE_WORKER,
        NULLIFY_AI
    }

    private final boolean wholesale;
    private final boolean hasWorkerTargets;
    private final boolean hasAiTargets;
    private final Map<String, Set<MutationAction>> classActions;
    private final Map<String, Set<MutationAction>> classMethodConstraints; // key: normClass -> actions with method constraints
    private final Map<String, Set<MutationAction>> methodActions; // key: "normClass#methodName"

    private MutationPlan(boolean wholesale,
                         boolean hasWorkerTargets,
                         boolean hasAiTargets,
                         Map<String, Set<MutationAction>> classActions,
                         Map<String, Set<MutationAction>> classMethodConstraints,
                         Map<String, Set<MutationAction>> methodActions) {
        this.wholesale = wholesale;
        this.hasWorkerTargets = hasWorkerTargets;
        this.hasAiTargets = hasAiTargets;
        this.classActions = Collections.unmodifiableMap(classActions);
        this.classMethodConstraints = Collections.unmodifiableMap(classMethodConstraints);
        this.methodActions = Collections.unmodifiableMap(methodActions);
    }

    /**
     * Creates an unrestricted/wholesale plan where all operations are permitted based on PrivacyOptions flags.
     */
    public static MutationPlan wholesale() {
        return new MutationPlan(true, false, false, Collections.emptyMap(), Collections.emptyMap(), Collections.emptyMap());
    }

    /**
     * Builds a targeted plan strictly containing the user-selected threats.
     */
    public static MutationPlan fromThreats(Collection<DetectedThreat> threats, PrivacyOptions options) {
        if (threats == null || threats.isEmpty()) {
            return new MutationPlan(false, false, false, Collections.emptyMap(), Collections.emptyMap(), Collections.emptyMap());
        }

        Map<String, Set<MutationAction>> classActions = new HashMap<>();
        Map<String, Set<MutationAction>> classMethodConstraints = new HashMap<>();
        Map<String, Set<MutationAction>> methodActions = new HashMap<>();
        boolean hasWorker = false;
        boolean hasAi = false;

        for (DetectedThreat threat : threats) {
            if (!threat.selectedForExcision) continue;
            String targetClass = normalizeClass(threat.targetClass);
            if (targetClass == null || targetClass.isEmpty() || targetClass.endsWith(".xml;")) continue;

            MutationAction action = mapCategoryToAction(threat, options);
            if (action == null) continue;

            if (action == MutationAction.NEUTRALIZE_WORKER) hasWorker = true;
            if (action == MutationAction.NULLIFY_AI) hasAi = true;

            classActions.computeIfAbsent(targetClass, k -> EnumSet.noneOf(MutationAction.class)).add(action);

            if (threat.targetMethod != null && !threat.targetMethod.isEmpty() && !threat.targetMethod.startsWith("<")) {
                classMethodConstraints.computeIfAbsent(targetClass, k -> EnumSet.noneOf(MutationAction.class)).add(action);
                String methodKey = targetClass + "#" + threat.targetMethod;
                methodActions.computeIfAbsent(methodKey, k -> EnumSet.noneOf(MutationAction.class)).add(action);
            }
        }

        return new MutationPlan(false, hasWorker, hasAi, classActions, classMethodConstraints, methodActions);
    }

    public static String normalizeClass(String raw) {
        if (raw == null) return null;
        String s = raw.trim();
        if (s.isEmpty()) return s;
        String inner = (s.startsWith("L") && s.endsWith(";")) ? s.substring(1, s.length() - 1) : s;
        return "L" + inner.replace('.', '/') + ";";
    }

    private static MutationAction mapCategoryToAction(DetectedThreat threat, PrivacyOptions options) {
        if (threat.category == DetectedThreat.Category.LOG_LEAK) {
            return MutationAction.STRIP_LOG;
        } else if (threat.category == DetectedThreat.Category.HARDWARE_FINGERPRINT) {
            String title = threat.title != null ? threat.title : "";
            if (title.contains("Android ID")) {
                return (options != null && (options.blankAndroidId || options.mode == SanitizationMode.AGGRESSIVE))
                        ? MutationAction.BLANK_ANDROID_ID
                        : null;
            } else if (title.contains("Telephony")) {
                return MutationAction.BLANK_TELEPHONY;
            } else if (title.contains("Advertising") || title.contains("Ad ID") || title.contains("GAID")) {
                return MutationAction.NEUTRALIZE_AD_ID;
            } else {
                return null;
            }
        } else if (threat.category == DetectedThreat.Category.SURVEILLANCE) {
            return MutationAction.MASK_DEV_MODE;
        } else if (threat.category == DetectedThreat.Category.TRACKER_SDK) {
            return MutationAction.SINKHOLE_DOMAIN;
        }
        return null;
    }

    public boolean isWholesale() {
        return wholesale;
    }

    public boolean hasTargetsForClass(String classDescriptor) {
        if (wholesale) return true;
        return classActions.containsKey(normalizeClass(classDescriptor));
    }

    public boolean allowsWorkerNeutralization(String classDescriptor) {
        if (wholesale) return true;
        if (hasWorkerTargets) {
            String norm = normalizeClass(classDescriptor);
            Set<MutationAction> actions = classActions.get(norm);
            return actions != null && actions.contains(MutationAction.NEUTRALIZE_WORKER);
        }
        return true;
    }

    public boolean allowsAiNullification(String classDescriptor) {
        if (wholesale) return true;
        if (hasAiTargets) {
            String norm = normalizeClass(classDescriptor);
            Set<MutationAction> actions = classActions.get(norm);
            return actions != null && actions.contains(MutationAction.NULLIFY_AI);
        }
        return true;
    }

    public boolean shouldPerformAction(String classDescriptor, String methodName, MutationAction action) {
        if (wholesale) return true;
        String normClass = normalizeClass(classDescriptor);
        Set<MutationAction> actions = classActions.get(normClass);
        if (actions == null || !actions.contains(action)) return false;

        Set<MutationAction> constraints = classMethodConstraints.get(normClass);
        if (constraints != null && constraints.contains(action)) {
            if (methodName == null) return false;
            String methodKey = normClass + "#" + methodName;
            Set<MutationAction> mActions = methodActions.get(methodKey);
            return mActions != null && mActions.contains(action);
        }

        return true;
    }

    public int targetedClassCount() {
        return classActions.size();
    }
}

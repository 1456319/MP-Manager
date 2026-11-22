# Sterilizer Reliability & Safe Mutation Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Overhaul the MP-Manager Privacy Sterilizer from category-wide heuristics into a surgical, reliable, split-aware bytecode mutation engine that guarantees application stability and zero false-positive mutations.

**Architecture:** Replace wholesale category-wide regex passes with a targeted Mutation Instruction Map derived directly from scanner findings. Enforce strict split-APK co-signing, protocol-compliant dummy return values (e.g. zeroed RFC UUIDs instead of empty strings), complete annotation preservation (Retrofit/Moshi/Hilt), and pre-flight/post-flight bytecode verification gates.

**Tech Stack:** Java, Dalvik/DEX bytecode (smali dexlib2), apkkit (com.reandroid), Android SDK build-tools (zipalign, apksigner), JUnit 4.

**Spec:** Audits and failure logs from Lovable review, Xfinity Digital Home (Tasks 11-15), and cashback app empirical runs (`com.upside.consumer.android`, `io.attaindata.boomerang`, `com.infoscout.receipthog`).

## Global Constraints

- Never mutate classes or methods outside the user-approved finding targets.
- Retain exact DEX header version (`dex\n039\0`, `dex\n038\0`, etc.) matching the input DEX.
- Maintain 100% of method, class, and parameter annotations across all transforms.
- Do not output a placebo `_sanitized.apk` if zero mutations are applied.
- All split APKs must be co-signed or bundled when modifying an application.

## Review Focus

1. **Split APK Signature Mismatch:** Android rejects install if `base.apk` signature differs from companion splits.
2. **Retrofit Parameter Annotation Loss:** Interface methods stripped of `@Query`/`@Path`/`@Header` crash at runtime with `IllegalArgumentException`.
3. **Empty String Malformed Inputs:** Replacing identifiers with `""` crashes apps calling `UUID.fromString()` or checking format.
4. **WorkManager Downstream NPEs:** Returning bare `Result.success()` without input data breaks data-dependent workers.
5. **DEX Version Header Downgrade:** Writing DEX 035 causes `IncompatibleClassChangeError` on modern Android interface default methods.

---

### Task 1: Fix Android ID Bleed & Safe Identifier Replacement

**Files:**
- Modify: `app/src/main/java/io/github/abdurazaaqmohammed/feature/apk/privacy/PrivacyBytecodeEngine.java:282-308`
- Modify: `app/src/main/java/io/github/abdurazaaqmohammed/feature/apk/privacy/PrivacyOptions.java:120-140`
- Test: `app/src/test/java/io/github/abdurazaaqmohammed/feature/apk/privacy/PrivacyBytecodeEngineTest.java`

- [ ] Step 1: Write a failing unit test `testAndroidIdNotBlankedWhenOptionDisabled` in `PrivacyBytecodeEngineTest.java` demonstrating that `options.blankAndroidId = false` in `Standard` mode currently blanks `android_id` due to `options.neutralizeAdIds`.
- [ ] Step 2: Run test to verify it fails:
  `./gradlew testFullDebugUnitTest --tests "io.github.abdurazaaqmohammed.feature.apk.privacy.PrivacyBytecodeEngineTest.testAndroidIdNotBlankedWhenOptionDisabled"`
- [ ] Step 3: Implement surgical fix in `PrivacyBytecodeEngine.java`: decouple `android_id` blanking from `neutralizeAdIds` so it strictly obeys `options.blankAndroidId || options.mode == SanitizationMode.AGGRESSIVE`.
- [ ] Step 4: When blanking is enabled, replace with standard 16-hex dummy `0000000000000000` or zeroed UUID `00000000-0000-0000-0000-000000000000` rather than empty string `""` to prevent downstream format parse crashes.
- [ ] Step 5: Run unit tests to verify fix passes:
  `./gradlew testFullDebugUnitTest --tests "io.github.abdurazaaqmohammed.feature.apk.privacy.PrivacyBytecodeEngineTest"`

---

### Task 2: Targeted Mutation Mapping (Decoupling Wholesale Category Passes)

**Files:**
- Create: `app/src/main/java/io/github/abdurazaaqmohammed/feature/apk/privacy/MutationPlan.java`
- Modify: `app/src/main/java/io/github/abdurazaaqmohammed/feature/apk/privacy/PrivacyBytecodeEngine.java`
- Test: `app/src/test/java/io/github/abdurazaaqmohammed/feature/apk/privacy/TargetedMutationPlanTest.java`

- [ ] Step 1: Write a failing unit test `TargetedMutationPlanTest.java` verifying that given a set of selected `PrivacyThreat` items, only the matching classes and method callsites are modified, leaving unrelated classes untouched.
- [ ] Step 2: Run test to confirm it fails.
- [ ] Step 3: Implement `MutationPlan.java`: an immutable container mapping specific target class descriptors and callsite signatures to targeted mutation operations (`STRIP_LOG`, `NEUTRALIZE_AD_ID`, `STUB_WORKER`, `SINKHOLE_DOMAIN`).
- [ ] Step 4: Refactor `PrivacyBytecodeEngine.sanitizeClass` to accept an optional `MutationPlan`. When a plan is present, check targets against the plan before mutating, replacing wholesale category switches.
- [ ] Step 5: Run tests and verify:
  `./gradlew testFullDebugUnitTest --tests "io.github.abdurazaaqmohammed.feature.apk.privacy.TargetedMutationPlanTest"`

---

### Task 3: Split APK Co-Discovery and Co-Signing Engine

**Files:**
- Modify: `app/src/main/java/io/github/abdurazaaqmohammed/feature/apk/privacy/PrivacyBytecodeEngine.java`
- Create: `app/src/main/java/io/github/abdurazaaqmohammed/feature/apk/privacy/ApkBundlePacker.java`
- Test: `app/src/test/java/io/github/abdurazaaqmohammed/feature/apk/privacy/ApkBundlePackerTest.java`

- [ ] Step 1: Write a failing test `ApkBundlePackerTest.java` verifying that when a split APK set is provided (`base.apk` + companion splits), `ApkBundlePacker` discovers all companion splits, re-signs all splits with the target keystore, and verifies signature consistency.
- [ ] Step 2: Run test to verify failure.
- [ ] Step 3: Implement `ApkBundlePacker.java` leveraging `apksigner` and `ApkModule` to handle split APK sets and generate co-signed installable sets.
- [ ] Step 4: Run test to verify passes:
  `./gradlew testFullDebugUnitTest --tests "io.github.abdurazaaqmohammed.feature.apk.privacy.ApkBundlePackerTest"`

---

### Task 4: Safe WorkManager Data Preservation & Telemetry Worker Stubbing

**Files:**
- Modify: `app/src/main/java/io/github/abdurazaaqmohammed/feature/apk/privacy/PrivacyBytecodeEngine.java:540-590`
- Test: `app/src/test/java/io/github/abdurazaaqmohammed/feature/apk/privacy/WorkerNeutralizationTest.java`

- [ ] Step 1: Write a failing test in `WorkerNeutralizationTest.java` verifying that a neutralized Worker preserves its input data via `Result.success(getInputData())` rather than `Result.success()` with empty Data.
- [ ] Step 2: Run test to verify failure.
- [ ] Step 3: Update `neutralizeWorkerClass` in `PrivacyBytecodeEngine.java` to invoke `this.getInputData()` and pass it to `ListenableWorker.Result.success(Data)`.
- [ ] Step 4: Run unit tests to verify passes.

---

### Task 5: Zero-Mutation Honesty Gate & Output Integrity Audit

**Files:**
- Modify: `app/src/main/java/io/github/abdurazaaqmohammed/feature/apk/privacy/PrivacyBytecodeEngine.java:860-970`
- Modify: `app/src/main/java/io/github/abdurazaaqmohammed/feature/apk/privacy/PrivacyAuditDialog.java`
- Test: `app/src/test/java/io/github/abdurazaaqmohammed/feature/apk/privacy/ZeroMutationAuditTest.java`

- [ ] Step 1: Write a failing test in `ZeroMutationAuditTest.java` verifying that when an APK undergoes sanitization but 0 mutations occur, the engine returns `Status.NOT_DETECTED` / `UNMODIFIED` and does NOT write an identical output APK or report "APK sanitized!".
- [ ] Step 2: Run test to verify failure.
- [ ] Step 3: Update `PrivacyBytecodeEngine.sanitizeApkWithAudit`: if `totalStats.totalMutations() == 0`, do not write `apkOut`, set `overallSanitizationStatus = Status.NOT_DETECTED`, and log honest notice.
- [ ] Step 4: Run unit tests to verify passes.

---

### Task 6: Empirical End-to-End Verification on Cashback Apps

**Files:**
- Test: `app/src/test/java/io/github/abdurazaaqmohammed/feature/apk/privacy/CashbackSanitizerEmpiricalTest.java`

- [ ] Step 1: Run full regression on `CashbackSanitizerEmpiricalTest` across Upside, Attain, Receipt Hog, and Joko.
- [ ] Step 2: Verify `zipalign -c 4` and `apksigner verify` on all produced binaries.
- [ ] Step 3: Verify zero Retrofit annotation loss and zero DEX version downgrade across all output DEX files.
- [ ] Step 4: On-device live validation via wireless ADB (`10.0.0.184:5555`) with ART OAT compilation check.

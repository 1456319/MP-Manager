package io.github.abdurazaaqmohammed.feature.apk.privacy;

import com.android.tools.smali.dexlib2.DexFileFactory;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction;
import com.android.tools.smali.dexlib2.iface.reference.MethodReference;
import com.android.tools.smali.smali.Smali;
import com.android.tools.smali.smali.SmaliOptions;
import org.junit.Test;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.util.Collections;

import static org.junit.Assert.*;

public class TargetedMutationPlanTest {

    private static final String TARGET_A_SMALI = """
            .class public Ltest/TargetA;
            .super Ljava/lang/Object;
            .source "TargetA.java"

            .method public constructor <init>()V
                .locals 1
                invoke-direct {p0}, Ljava/lang/Object;-><init>()V
                return-void
            .end method

            .method public logMessage()V
                .locals 2
                const-string v0, "TagA"
                const-string v1, "MessageA"
                invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
                return-void
            .end method
            """;

    private static final String TARGET_B_SMALI = """
            .class public Ltest/TargetB;
            .super Ljava/lang/Object;
            .source "TargetB.java"

            .method public constructor <init>()V
                .locals 1
                invoke-direct {p0}, Ljava/lang/Object;-><init>()V
                return-void
            .end method

            .method public logMessage()V
                .locals 2
                const-string v0, "TagB"
                const-string v1, "MessageB"
                invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
                return-void
            .end method
            """;

    private static final String TARGET_MULTI_SMALI = """
            .class public Ltest/TargetMulti;
            .super Ljava/lang/Object;
            .source "TargetMulti.java"

            .method public constructor <init>()V
                .locals 1
                invoke-direct {p0}, Ljava/lang/Object;-><init>()V
                return-void
            .end method

            .method public targetedMethod()V
                .locals 2
                const-string v0, "Tag1"
                const-string v1, "Message1"
                invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
                return-void
            .end method

            .method public preservedMethod()V
                .locals 2
                const-string v0, "Tag2"
                const-string v1, "Message2"
                invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
                return-void
            .end method
            """;

    private File assembleSmali(String smaliCode, String className) throws Exception {
        File dir = Files.createTempDirectory("plan_test_" + className).toFile();
        File pkg = new File(dir, "test");
        assertTrue(pkg.mkdirs());
        try (FileWriter w = new FileWriter(new File(pkg, className + ".smali"))) {
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
    public void testTargetedPlanMutatesOnlySelectedClass() throws Exception {
        File dexAFile = assembleSmali(TARGET_A_SMALI, "TargetA");
        File dexBFile = assembleSmali(TARGET_B_SMALI, "TargetB");

        DexBackedDexFile dexA = DexFileFactory.loadDexFile(dexAFile, Opcodes.getDefault());
        DexBackedDexFile dexB = DexFileFactory.loadDexFile(dexBFile, Opcodes.getDefault());

        ClassDef classA = dexA.getClasses().iterator().next();
        ClassDef classB = dexB.getClasses().iterator().next();

        // Target ONLY Class A for log stripping
        DetectedThreat threatA = new DetectedThreat(
                DetectedThreat.Category.LOG_LEAK,
                "Logging leak in TargetA",
                "Sensitive log",
                "Ltest/TargetA;",
                "logMessage",
                DetectedThreat.ExcisionType.NOP_INVOKE,
                false
        );
        threatA.selectedForExcision = true;

        MutationPlan plan = MutationPlan.fromThreats(Collections.singletonList(threatA), PrivacyOptions.standard());
        assertTrue("Plan must have TargetA", plan.hasTargetsForClass("Ltest/TargetA;"));
        assertFalse("Plan must NOT have TargetB", plan.hasTargetsForClass("Ltest/TargetB;"));

        // Sanitize Target A -> Must be modified
        PrivacyStats statsA = new PrivacyStats();
        ClassDef sanitizedA = PrivacyBytecodeEngine.sanitizeClass(classA, PrivacyOptions.standard(), statsA, null, plan);
        assertEquals("Target A must have 1 log call stripped", 1, statsA.logCallsStripped);
        assertNotSame(classA, sanitizedA);

        // Sanitize Target B with same plan -> Must be completely untouched!
        PrivacyStats statsB = new PrivacyStats();
        ClassDef sanitizedB = PrivacyBytecodeEngine.sanitizeClass(classB, PrivacyOptions.standard(), statsB, null, plan);
        assertEquals("Target B must have 0 logs stripped", 0, statsB.logCallsStripped);
        assertSame("Target B should be identical instance when not targeted", classB, sanitizedB);
    }

    @Test
    public void testMethodLevelTargetingPrecision() throws Exception {
        File dexFile = assembleSmali(TARGET_MULTI_SMALI, "TargetMulti");
        DexBackedDexFile dex = DexFileFactory.loadDexFile(dexFile, Opcodes.getDefault());
        ClassDef classDef = dex.getClasses().iterator().next();

        // Target ONLY targetedMethod, NOT preservedMethod
        DetectedThreat threat = new DetectedThreat(
                DetectedThreat.Category.LOG_LEAK,
                "Log in targetedMethod",
                "Sensitive log",
                "Ltest/TargetMulti;",
                "targetedMethod",
                DetectedThreat.ExcisionType.NOP_INVOKE,
                false
        );
        threat.selectedForExcision = true;

        MutationPlan plan = MutationPlan.fromThreats(Collections.singletonList(threat), PrivacyOptions.standard());

        PrivacyStats stats = new PrivacyStats();
        ClassDef sanitized = PrivacyBytecodeEngine.sanitizeClass(classDef, PrivacyOptions.standard(), stats, null, plan);

        assertEquals("Only targetedMethod should have its log stripped", 1, stats.logCallsStripped);

        // Verify that targetedMethod has Log call stripped (NOP) and preservedMethod still has Log.d
        for (Method m : sanitized.getVirtualMethods()) {
            if ("targetedMethod".equals(m.getName())) {
                boolean hasLogCall = false;
                for (Instruction inst : m.getImplementation().getInstructions()) {
                    if (inst instanceof ReferenceInstruction && ((ReferenceInstruction) inst).getReference() instanceof MethodReference) {
                        MethodReference mr = (MethodReference) ((ReferenceInstruction) inst).getReference();
                        if ("Landroid/util/Log;".equals(mr.getDefiningClass())) hasLogCall = true;
                    }
                }
                assertFalse("targetedMethod must have Log call stripped", hasLogCall);
            } else if ("preservedMethod".equals(m.getName())) {
                boolean hasLogCall = false;
                for (Instruction inst : m.getImplementation().getInstructions()) {
                    if (inst instanceof ReferenceInstruction && ((ReferenceInstruction) inst).getReference() instanceof MethodReference) {
                        MethodReference mr = (MethodReference) ((ReferenceInstruction) inst).getReference();
                        if ("Landroid/util/Log;".equals(mr.getDefiningClass())) hasLogCall = true;
                    }
                }
                assertTrue("preservedMethod MUST retain its original Log call", hasLogCall);
            }
        }
    }

    @Test
    public void testDescriptorNormalizationVariations() {
        assertEquals("Lcom/example/Foo;", MutationPlan.normalizeClass("com.example.Foo"));
        assertEquals("Lcom/example/Foo;", MutationPlan.normalizeClass("Lcom/example/Foo;"));
        assertEquals("Lcom/example/Foo;", MutationPlan.normalizeClass("Lcom.example.Foo;"));
        assertEquals("Lcom/example/Foo;", MutationPlan.normalizeClass("  Lcom.example.Foo;  "));
    }

    @Test
    public void testUnselectedThreatIsExcludedFromPlan() {
        DetectedThreat threat = new DetectedThreat(
                DetectedThreat.Category.LOG_LEAK,
                "Log leak",
                "Log",
                "Ltest/TargetA;",
                "logMessage",
                DetectedThreat.ExcisionType.NOP_INVOKE,
                false
        );
        threat.selectedForExcision = false; // User unchecked the finding!

        MutationPlan plan = MutationPlan.fromThreats(Collections.singletonList(threat), PrivacyOptions.standard());
        assertFalse("Unchecked threat must NOT be targeted in plan", plan.hasTargetsForClass("Ltest/TargetA;"));
        assertEquals(0, plan.targetedClassCount());
    }
}

package com.owasp.demo.util;

import java.util.List;
import java.util.Set;

/**
 * Compares this JVM and CPU with the conditions listed for Java4Shell
 * (CVE-2026-114938), the OpenJDK Base64 decoder memory corruption.
 * It reads no state itself. The caller passes the facts in.
 * It cannot see the vendor's patch level, so it never says "patched".
 */
public final class JvmExposureCheck {

    /** The verdict. */
    public enum Verdict { NOT_EXPOSED, MITIGATED, POSSIBLY_EXPOSED }

    /**
     * @param verdict the overall result
     * @param message one sentence that explains the verdict
     */
    public record Result(Verdict verdict, String message) {}

    private JvmExposureCheck() {}

    /**
     * Applies the advisory's conditions in order.
     *
     * @param javaFeature the Java feature release, such as 21
     * @param osArch the os.arch value, such as amd64 or aarch64
     * @param cpuFlags the CPU flag names, or null if they cannot be read
     * @param jvmArgs the JVM start-up arguments
     * @param affectedFeatures Java feature releases named in the advisory
     * @param requiredCpuFlags CPU flags the shortcut needs
     * @param mitigationFlags JVM flags that switch the shortcut off
     * @return the verdict and a one-line reason
     */
    public static Result assess(int javaFeature, String osArch, Set<String> cpuFlags, List<String> jvmArgs,
                                List<Integer> affectedFeatures, List<String> requiredCpuFlags,
                                List<String> mitigationFlags) {
        if (!affectedFeatures.contains(javaFeature)) {
            return new Result(Verdict.NOT_EXPOSED,
                "Java " + javaFeature + " is not one of the affected lines " + affectedFeatures + ".");
        }
        if (!isX86(osArch)) {
            return new Result(Verdict.NOT_EXPOSED,
                "The flaw needs an x86-64 CPU. This one is " + osArch + ".");
        }
        for (String arg : jvmArgs) {
            if (mitigationFlags.contains(arg)) {
                return new Result(Verdict.MITIGATED, "The JVM runs with " + arg + ", which avoids the faulty shortcut.");
            }
        }
        if (cpuFlags != null && !cpuFlags.containsAll(requiredCpuFlags)) {
            return new Result(Verdict.NOT_EXPOSED,
                "The CPU lacks the AVX-512 features the shortcut needs " + requiredCpuFlags + ".");
        }
        String cpuNote = cpuFlags == null ? " CPU flags could not be read here." : "";
        return new Result(Verdict.POSSIBLY_EXPOSED,
            "Java " + javaFeature + " on x86-64 with no mitigation flag. Compare the build number with the fixed builds." + cpuNote);
    }

    private static boolean isX86(String osArch) {
        return "amd64".equalsIgnoreCase(osArch) || "x86_64".equalsIgnoreCase(osArch);
    }
}

package com.owasp.demo.util;

import com.owasp.demo.util.JvmExposureCheck.Verdict;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class JvmExposureCheckTest {

    private static final List<Integer> AFFECTED = List.of(17, 21, 25, 27);
    private static final List<String> NEEDED = List.of("avx512f", "avx512bw", "avx512vbmi", "bmi2");
    private static final List<String> FLAGS = List.of("-XX:-UseBASE64Intrinsics", "-XX:UseAVX=2");
    private static final Set<String> ALL_CPU = Set.of("avx512f", "avx512bw", "avx512vbmi", "bmi2", "sse4_2");

    private Verdict check(int java, String arch, Set<String> cpu, List<String> args) {
        return JvmExposureCheck.assess(java, arch, cpu, args, AFFECTED, NEEDED, FLAGS).verdict();
    }

    @Test
    void unaffectedJavaLine_isNotExposed() {
        assertEquals(Verdict.NOT_EXPOSED, check(11, "amd64", ALL_CPU, List.of()));
        assertEquals(Verdict.NOT_EXPOSED, check(8, "amd64", ALL_CPU, List.of()));
    }

    @Test
    void arm64_isNotExposed() {
        assertEquals(Verdict.NOT_EXPOSED, check(21, "aarch64", null, List.of()));
    }

    @Test
    void mitigationFlag_isReportedAsMitigated() {
        assertEquals(Verdict.MITIGATED, check(21, "amd64", ALL_CPU, List.of("-Xmx1g", "-XX:-UseBASE64Intrinsics")));
        assertEquals(Verdict.MITIGATED, check(17, "x86_64", ALL_CPU, List.of("-XX:UseAVX=2")));
    }

    @Test
    void cpuWithoutAvx512Vbmi_isNotExposed() {
        assertEquals(Verdict.NOT_EXPOSED, check(21, "amd64", Set.of("avx2", "sse4_2"), List.of()));
    }

    @Test
    void affectedJavaOnCapableCpu_isPossiblyExposed() {
        assertEquals(Verdict.POSSIBLY_EXPOSED, check(21, "amd64", ALL_CPU, List.of()));
    }

    @Test
    void unreadableCpuFlags_isPossiblyExposedAndSaysSo() {
        var r = JvmExposureCheck.assess(25, "amd64", null, List.of(), AFFECTED, NEEDED, FLAGS);
        assertEquals(Verdict.POSSIBLY_EXPOSED, r.verdict());
        assertTrue(r.message().contains("could not be read"));
    }
}

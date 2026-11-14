import { describe, expect, it } from "vitest";
import { BenchmarkRunner } from "./BenchmarkRunner.js";
import { getStandardBenchmarkCorpus } from "./corpus.js";

describe("Phase 7D: Standard Benchmark Corpus Execution & Metric Calculation", () => {
  const runner = new BenchmarkRunner();
  const corpus = getStandardBenchmarkCorpus();

  it("evaluates all samples in the corpus across ARM, MIPS, and x86_64", async () => {
    expect(corpus.length).toBe(8);

    const report = await runner.evaluateCorpus(corpus);
    expect(report.totalSamples).toBe(8);
    expect(report.evaluations.length).toBe(8);

    // Verify all architectures are represented
    const archs = corpus.map((s) => s.architecture);
    expect(archs).toContain("ARM");
    expect(archs).toContain("MIPS");
    expect(archs).toContain("x86_64");

    // All evaluations have an execution duration
    for (const ev of report.evaluations) {
      expect(ev.executionTimeMs).toBeGreaterThanOrEqual(0);
    }
  });

  it("achieves 100% precision on proof-level verification without false positives", async () => {
    const report = await runner.evaluateCorpus(corpus);
    const proof = report.proofVerificationMetrics;

    // Proof verification must have ZERO false positives
    expect(proof.falsePositives).toBe(0);
    expect(proof.precision).toBe(1.0);
    expect(proof.recall).toBeGreaterThanOrEqual(0.75);
    expect(proof.f1Score).toBeGreaterThanOrEqual(0.8);

    // True positives correspond strictly to VULNERABLE samples
    expect(proof.truePositives).toBe(3); // ARM-VULN, MIPS-VULN, X86-VULN
  });
});

describe("Phase 7D: Adjudication Discrimination & Evidence Reproducibility", () => {
  const runner = new BenchmarkRunner();
  const corpus = getStandardBenchmarkCorpus();

  it("correctly discriminates false positives, mitigated guards, and inconclusive cases", async () => {
    const report = await runner.evaluateCorpus(corpus);

    const fpConstant = report.evaluations.find((e) => e.sampleId === "ARM-FP-001-CONSTANT-ARG");
    expect(fpConstant?.adjudicatedState).toBe("FALSE_POSITIVE");

    const fpDeadCode = report.evaluations.find((e) => e.sampleId === "ARM-FP-002-DEAD-CODE");
    expect(fpDeadCode?.adjudicatedState).toBe("FALSE_POSITIVE");

    const mitigated = report.evaluations.find((e) => e.sampleId === "ARM-FIXED-001-CMD-SANITIZED");
    expect(mitigated?.adjudicatedState).toBe("MITIGATED");

    const inconclusive = report.evaluations.find((e) => e.sampleId === "X86-INCONCL-001-INDIRECT-CALL");
    expect(inconclusive?.adjudicatedState).toBe("INCONCLUSIVE");

    const verifiedArm = report.evaluations.find((e) => e.sampleId === "ARM-VULN-001-CMD-INJECTION");
    expect(verifiedArm?.adjudicatedState).toBe("VERIFIED");
  });

  it("maintains high verification coverage and reproducible evidence tracking", async () => {
    const report = await runner.evaluateCorpus(corpus);

    // Coverage of definitive outcomes (VERIFIED, MITIGATED, FALSE_POSITIVE)
    expect(report.verificationCoverage).toBeGreaterThanOrEqual(0.75);

    // All candidate-detected samples produce verifiable evidence records
    expect(report.reproducibleEvidencePercentage).toBeGreaterThanOrEqual(0.75);

    // Candidate detection metrics separate from proof metrics
    const cand = report.candidateMetrics;
    expect(cand.truePositives).toBeGreaterThanOrEqual(6);
    expect(cand.accuracy).toBeGreaterThanOrEqual(0.85);
  });
});

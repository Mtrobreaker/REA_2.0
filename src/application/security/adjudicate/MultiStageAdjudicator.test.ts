import { describe, it, expect } from "vitest";
import { MultiStageAdjudicator } from "./MultiStageAdjudicator.js";
import type { AdjudicationContext } from "../../../domain/security/adjudicate/types.js";
import type { FindingId } from "../../../domain/security/finding.js";

describe("MultiStageAdjudicator", () => {
  const adjudicator = new MultiStageAdjudicator();
  const findingId = "fnd_1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff" as FindingId;

  it("rejects hallucinated guard that only exists in a code comment", () => {
    const source = `
      void process_data(char *input, int len) {
        // if (len < 1024) return;
        char buffer[1024];
        memcpy(buffer, input, len);
      }
    `;

    const context: AdjudicationContext = {
      finding_id: findingId,
      source_code: source,
      file_path: "src/net.c",
      language: "c",
      claimed_guard_expression: "len < 1024",
      sink_expression: "memcpy(buffer, input, len)",
      sink_line: 5,
      tainted_variable: "len",
      evidence_category: "STATIC_AST_CFG",
    };

    const res = adjudicator.adjudicate(context);
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    // The guard was in a comment: hallucination rejected!
    expect(res.value.outcome).toBe("CONFIRMED_VULNERABLE");
    expect(res.value.reasoning).toContain("does not physically exist in executable source");
    expect(res.value.confidence_score).toBe(0.8);
  });

  it("detects flawed guard checking the wrong operand", () => {
    const source = `
      void process_data(char *input, int count, int len) {
        if (count < 1024) {
          char buffer[1024];
          memcpy(buffer, input, len); // Flaw: len is unchecked!
        }
      }
    `;

    const context: AdjudicationContext = {
      finding_id: findingId,
      source_code: source,
      file_path: "src/net.c",
      language: "c",
      claimed_guard_expression: "count < 1024",
      claimed_guard_line: 3,
      sink_expression: "memcpy(buffer, input, len)",
      sink_line: 5,
      tainted_variable: "len", // We care about len, not count
      evidence_category: "STATIC_AST_CFG",
    };

    const res = adjudicator.adjudicate(context);
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    expect(res.value.outcome).toBe("FLAWED_GUARD");
    expect(res.value.reasoning).toContain("Guard tests wrong operand");
    expect(res.value.dominating_guard?.operand_matched).toBe(false);
  });

  it("detects flawed guard placed after the sensitive sink", () => {
    const source = `
      void process_data(char *input, int len) {
        char buffer[1024];
        memcpy(buffer, input, len);
        if (len < 1024) {
          log("Processed successfully");
        }
      }
    `;

    const context: AdjudicationContext = {
      finding_id: findingId,
      source_code: source,
      file_path: "src/net.c",
      language: "c",
      claimed_guard_expression: "len < 1024",
      claimed_guard_line: 5, // After the sink on line 4!
      sink_expression: "memcpy(buffer, input, len)",
      sink_line: 4,
      tainted_variable: "len",
      evidence_category: "STATIC_AST_CFG",
    };

    const res = adjudicator.adjudicate(context);
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    expect(res.value.outcome).toBe("FLAWED_GUARD");
    expect(res.value.reasoning).toContain("does not dominate sink");
    expect(res.value.dominating_guard?.dominates_all_paths).toBe(false);
  });

  it("confirms mitigation when a sound dominating bounds check exists", () => {
    const source = `
      void process_data(char *input, int len) {
        if (len < 0 || len >= 1024) {
          return;
        }
        char buffer[1024];
        memcpy(buffer, input, len);
      }
    `;

    const context: AdjudicationContext = {
      finding_id: findingId,
      source_code: source,
      file_path: "src/net.c",
      language: "c",
      claimed_guard_expression: "len >= 1024",
      claimed_guard_line: 3,
      sink_expression: "memcpy(buffer, input, len)",
      sink_line: 7,
      tainted_variable: "len",
      evidence_category: "STATIC_AST_CFG",
    };

    const res = adjudicator.adjudicate(context);
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    expect(res.value.outcome).toBe("CONFIRMED_MITIGATED");
    expect(res.value.confidence_score).toBe(0.75); // Capped by static analysis ceiling
    expect(res.value.dominating_guard?.dominates_all_paths).toBe(true);
    expect(res.value.dominating_guard?.operand_matched).toBe(true);
  });

  it("restricts synthetic fixture confidence to ceiling (does not report 1.0)", () => {
    const source = `
      void test_harness() {
        assert(safe_len < 100);
      }
    `;

    const context: AdjudicationContext = {
      finding_id: findingId,
      source_code: source,
      file_path: "tests/harness.c",
      language: "c",
      claimed_guard_expression: "safe_len < 100",
      tainted_variable: "safe_len",
      evidence_category: "SYNTHETIC_FIXTURE", // Synthetic fixture!
    };

    const res = adjudicator.adjudicate(context);
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    // Must not falsely award 1.0 confidence for a synthetic fixture
    expect(res.value.confidence_score).toBeLessThanOrEqual(0.85);
  });

  it("returns INCONCLUSIVE when source code is missing or empty", () => {
    const context: AdjudicationContext = {
      finding_id: findingId,
      source_code: "",
      file_path: "src/unknown.c",
      evidence_category: "STATIC_AST_CFG",
    };

    const res = adjudicator.adjudicate(context);
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    expect(res.value.outcome).toBe("INCONCLUSIVE");
    expect(res.value.reasoning).toContain("Source code missing or unavailable");
  });
});


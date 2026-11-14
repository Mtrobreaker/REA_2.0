import { describe, it, expect } from "vitest";
import { MultiStageAdjudicator } from "./MultiStageAdjudicator.js";
import { blankSourceCode, guardExistsInExecutableSource } from "./LexicalBlanker.js";
import type { AdjudicationContext } from "../../../domain/security/adjudicate/types.js";
import type { FindingId } from "../../../domain/security/finding.js";

const findingId = "fnd_bench000000000000000000000000000000000000000000000000000000000" as FindingId;

describe("Adjudicate 10-Language Comment & Literal Blanking Pipeline", () => {
  it("blanks Python line comments and docstring triple-quotes without corrupting code", () => {
    const pyCode = `
def parse(data, size):
    """
    Docstring: if size < 100: return
    """
    # if size < 100: return
    if size < 50:
        return True
    `;
    const blanked = blankSourceCode(pyCode, "python");
    expect(blanked).not.toContain("Docstring");
    expect(blanked).not.toContain("# if size < 100");
    expect(blanked).toContain("if size < 50:");

    expect(guardExistsInExecutableSource(pyCode, "size < 100", "python").exists).toBe(false);
    expect(guardExistsInExecutableSource(pyCode, "size < 50", "python").exists).toBe(true);
  });

  it("blanks C/C++/Java/Rust/Go block and line comments", () => {
    const cCode = `
      /* Block comment: if (len < 64) exit(1); */
      // Line comment: if (len < 128) exit(1);
      if (len < 256) {
        exit(1);
      }
    `;
    const blanked = blankSourceCode(cCode, "c");
    expect(blanked).not.toContain("Block comment");
    expect(blanked).not.toContain("Line comment");
    expect(blanked).toContain("if (len < 256)");

    expect(guardExistsInExecutableSource(cCode, "len < 64", "c").exists).toBe(false);
    expect(guardExistsInExecutableSource(cCode, "len < 128", "c").exists).toBe(false);
    expect(guardExistsInExecutableSource(cCode, "len < 256", "c").exists).toBe(true);
  });

  it("blanks JavaScript / TypeScript template literals and line comments", () => {
    const tsCode = `
      const msg = \`Log message with fake guard: if (count < 10) return;\`;
      // Line comment
      if (count < 5) return;
    `;
    expect(guardExistsInExecutableSource(tsCode, "count < 10", "typescript").exists).toBe(false);
    expect(guardExistsInExecutableSource(tsCode, "count < 5", "typescript").exists).toBe(true);
  });

  it("blanks Shell and SQL line comments", () => {
    const shCode = `
      # if [ "$len" -lt 10 ]; then exit 1; fi
      if [ "$len" -lt 5 ]; then exit 1; fi
    `;
    expect(guardExistsInExecutableSource(shCode, "len -lt 10", "shell").exists).toBe(false);

    const sqlCode = `
      -- WHERE id < 10
      WHERE id < 5
    `;
    expect(guardExistsInExecutableSource(sqlCode, "id < 10", "sql").exists).toBe(false);
  });
});

describe("Adjudicate Flawed Guard Semantic Soundness Suite", () => {
  const adjudicator = new MultiStageAdjudicator();

  it("detects wrong operand in guard", () => {
    const src = `
      void handle(char *buf, int actual_len, int fake_len) {
        if (fake_len < 128) {
          memcpy(buf, input, actual_len);
        }
      }
    `;
    const ctx: AdjudicationContext = {
      finding_id: findingId,
      source_code: src,
      file_path: "src/handle.c",
      language: "c",
      claimed_guard_expression: "fake_len < 128",
      sink_expression: "memcpy(buf, input, actual_len)",
      tainted_variable: "actual_len",
      evidence_category: "STATIC_AST_CFG",
    };

    const res = adjudicator.adjudicate(ctx);
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.outcome).toBe("FLAWED_GUARD");
    expect(res.value.reasoning).toContain("Guard tests wrong operand");
  });

  it("detects signedness vulnerability: signed integer missing non-negative check", () => {
    const src = `
      void handle(char *buf, int len) {
        if (len < 128) {
          memcpy(buf, input, len);
        }
      }
    `;
    const ctx: AdjudicationContext = {
      finding_id: findingId,
      source_code: src,
      file_path: "src/handle.c",
      language: "c",
      claimed_guard_expression: "len < 128",
      sink_expression: "memcpy(buf, input, len)",
      tainted_variable: "len",
      evidence_category: "STATIC_AST_CFG",
    };

    const res = adjudicator.adjudicate(ctx);
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.outcome).toBe("FLAWED_GUARD");
    expect(res.value.reasoning).toContain("without non-negative check");
  });

  it("returns INCONCLUSIVE when control flow has dynamic jumps (setjmp)", () => {
    const src = `
      void handle(char *buf, int len) {
        if (setjmp(env)) return;
        if (len >= 0 && len < 128) {
          memcpy(buf, input, len);
        }
      }
    `;
    const ctx: AdjudicationContext = {
      finding_id: findingId,
      source_code: src,
      file_path: "src/handle.c",
      language: "c",
      claimed_guard_expression: "len < 128",
      tainted_variable: "len",
      evidence_category: "STATIC_AST_CFG",
    };

    const res = adjudicator.adjudicate(ctx);
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.outcome).toBe("INCONCLUSIVE");
    expect(res.value.confidence_score).toBe(0.4);
  });

  it("confirms mitigation when a signedness-safe, dominating bounds check exists", () => {
    const src = `
      void handle(char *buf, int len) {
        if (len >= 0 && len < 128) {
          memcpy(buf, input, len);
        }
      }
    `;
    const ctx: AdjudicationContext = {
      finding_id: findingId,
      source_code: src,
      file_path: "src/handle.c",
      language: "c",
      claimed_guard_expression: "len < 128",
      sink_expression: "memcpy(buf, input, len)",
      tainted_variable: "len",
      evidence_category: "STATIC_AST_CFG",
    };

    const res = adjudicator.adjudicate(ctx);
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.outcome).toBe("CONFIRMED_MITIGATED");
    expect(res.value.confidence_score).toBeLessThanOrEqual(0.8);
  });
});

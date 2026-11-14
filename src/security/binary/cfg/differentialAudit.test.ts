import fs from "node:fs";
import { describe, expect, it } from "vitest";
import { InstructionDecoder } from "./InstructionDecoder.js";
import { ControlFlowGraphBuilder } from "./ControlFlowGraphBuilder.js";
import type { Architecture } from "./types.js";

interface LlvmInst {
  readonly address: number;
  readonly mnemonic: string;
  readonly operands: string;
  readonly size: number;
}

interface CorpusEntry {
  readonly name: string;
  readonly arch: string;
  readonly rea_arch: Architecture;
  readonly opt: string;
  readonly isThumb: boolean;
  readonly isLE: boolean;
  readonly raw_hex: string;
  readonly byte_count: number;
  readonly llvm_instruction_count: number;
  readonly llvm_instructions: readonly LlvmInst[];
}

const corpusPath =
  "C:/Users/acer/.gemini/antigravity/brain/a5d5c0a2-11df-475b-a7af-fd0c88384a83/scratch/differential_corpus.json";

describe("Phase 2.1: Independent Differential Conformance Audit vs llvm-objdump", () => {
  const decoder = new InstructionDecoder();
  const cfgBuilder = new ControlFlowGraphBuilder();
  let corpus: readonly CorpusEntry[] = [];

  if (fs.existsSync(corpusPath)) {
    corpus = JSON.parse(fs.readFileSync(corpusPath, "utf8"));
  }

  it("evaluates differential conformance across all compiled binaries", () => {
    expect(corpus.length).toBeGreaterThan(0);

    const auditSummary: Record<string, unknown>[] = [];

    for (const entry of corpus) {
      const rawBytes = Buffer.from(entry.raw_hex, "hex");
      const reaInsts = decoder.decode(rawBytes, 0, {
        architecture: entry.rea_arch,
        isThumb: entry.isThumb,
        isLittleEndian: entry.isLE,
      });

      const llvmMap = new Map<number, LlvmInst>();
      for (const inst of entry.llvm_instructions) {
        llvmMap.set(inst.address, inst);
      }

      let boundaryMatches = 0;
      let sizeMatches = 0;
      let unsupportedCount = 0;
      const desyncPoints: string[] = [];

      for (const inst of reaInsts) {
        if (
          inst.mnemonic.startsWith("db") ||
          inst.mnemonic === "arm_inst" ||
          inst.mnemonic === "thumb16_inst" ||
          inst.mnemonic === "mips_inst"
        ) {
          unsupportedCount++;
        }

        const llvm = llvmMap.get(inst.address);
        if (llvm) {
          boundaryMatches++;
          if (inst.size === llvm.size) {
            sizeMatches++;
          }
        } else {
          desyncPoints.push(`0x${inst.address.toString(16)} (${inst.mnemonic})`);
        }
      }

      const boundaryAcc = (boundaryMatches / Math.max(1, reaInsts.length)) * 100;
      const sizeAcc = (sizeMatches / Math.max(1, reaInsts.length)) * 100;
      const unsupportedRate = (unsupportedCount / Math.max(1, reaInsts.length)) * 100;

      const cfg = cfgBuilder.buildFunctionCfg(reaInsts, {
        functionName: entry.name,
        entryAddress: 0,
        architecture: entry.rea_arch,
      });

      auditSummary.push({
        binary: entry.name,
        arch: entry.arch,
        opt: entry.opt,
        llvmCount: entry.llvm_instruction_count,
        reaCount: reaInsts.length,
        boundaryAccuracy: `${boundaryAcc.toFixed(1)}%`,
        sizeAccuracy: `${sizeAcc.toFixed(1)}%`,
        unsupportedRate: `${unsupportedRate.toFixed(1)}%`,
        cfgBlocks: cfg.blocks.size,
        cfgEdges: cfg.edges.length,
        firstDesync: desyncPoints[0] ?? "none",
      });
    }

    console.log("=== DIFFERENTIAL AUDIT RESULTS ===");
    console.table(auditSummary);

    fs.writeFileSync(
      "C:/Users/acer/.gemini/antigravity/brain/a5d5c0a2-11df-475b-a7af-fd0c88384a83/scratch/audit_table.json",
      JSON.stringify(auditSummary, null, 2),
    );
  });
});


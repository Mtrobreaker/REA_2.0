import type { Architecture } from "./types.js";
import type {
  FunctionBoundaryStatus,
  FunctionEntrySource,
  FunctionRecoveryResult,
  Instruction,
  RecoveredFunction,
} from "./types.js";
import { ControlFlowGraphBuilder } from "./ControlFlowGraphBuilder.js";

export interface SymbolEntry {
  readonly name: string;
  readonly address: number;
  readonly size?: number;
  readonly isExport?: boolean;
  readonly isMips16?: boolean;
}

export interface ElfMetadata {
  readonly entryPoint?: number;
  readonly dtInit?: number;
  readonly dtFini?: number;
  readonly initArray?: readonly number[];
  readonly finiArray?: readonly number[];
}

export interface FunctionRecoveryOptions {
  readonly architecture: Architecture;
  readonly baseAddress: number;
  readonly totalCodeBytes: number;
  readonly symbols?: readonly SymbolEntry[];
  readonly elfMetadata?: ElfMetadata;
}

interface CandidateEntry {
  readonly address: number;
  name: string;
  source: FunctionEntrySource;
  isaMode: "MIPS32" | "MIPS16" | "ARM" | "Thumb" | "x86_64";
  priority: number; // Higher number takes precedence
}

const SOURCE_PRIORITY: Record<FunctionEntrySource, number> = {
  EXPORT_SYMBOL: 10,
  LOCAL_SYMBOL: 9,
  ELF_ENTRY: 8,
  DT_INIT: 7,
  DT_FINI: 7,
  INIT_ARRAY: 6,
  FINI_ARRAY: 6,
  PLT_STUB: 5,
  PROLOGUE_SIGNATURE: 4,
  DIRECT_CALL_TARGET: 3,
  CONTROL_FLOW_INFERENCE: 1,
};

/**
 * Conforming Function Recovery Engine.
 *
 * Discovers function entries and boundaries from ELF metadata, exported and
 * local symbols, direct call targets, and prologue signatures (MIPS16 save and
 * MIPS32 stack frame/PIC setups).
 *
 * Strictly models boundaries with typed verification status ("VERIFIED" vs "INFERRED")
 * and records direct calls, indirect calls, returns, tail calls, and basic block counts.
 */
export class FunctionRecoveryEngine {
  private readonly cfgBuilder = new ControlFlowGraphBuilder();

  public recoverFunctions(
    instructions: readonly Instruction[],
    options: FunctionRecoveryOptions,
  ): FunctionRecoveryResult {
    if (instructions.length === 0) {
      return {
        functions: [],
        totalRecovered: 0,
        verifiedBoundariesCount: 0,
        inferredBoundariesCount: 0,
        mips16FunctionsCount: 0,
        mips32FunctionsCount: 0,
      };
    }

    const codeStart = options.baseAddress >>> 0;
    const codeEnd = (options.baseAddress + options.totalCodeBytes) >>> 0;

    const instMap = new Map<number, { inst: Instruction; index: number }>();
    for (let i = 0; i < instructions.length; i++) {
      const inst = instructions[i]!;
      instMap.set(inst.address >>> 0, { inst, index: i });
    }

    const candidateMap = new Map<number, CandidateEntry>();

    const addCandidate = (
      addr: number,
      name: string,
      source: FunctionEntrySource,
      isaMode: "MIPS32" | "MIPS16" | "ARM" | "Thumb" | "x86_64",
    ) => {
      const normAddr = (addr & ~1) >>> 0;
      if (normAddr < codeStart || normAddr >= codeEnd) {
        return;
      }
      if (!instMap.has(normAddr)) {
        return;
      }

      const priority = SOURCE_PRIORITY[source];
      const existing = candidateMap.get(normAddr);

      if (!existing) {
        candidateMap.set(normAddr, {
          address: normAddr,
          name,
          source,
          isaMode,
          priority,
        });
      } else if (priority > existing.priority) {
        existing.name = name || existing.name;
        existing.source = source;
        existing.isaMode = isaMode;
        existing.priority = priority;
      }
    };

    // 1. Ingest ELF metadata entry points
    if (options.elfMetadata) {
      const { entryPoint, dtInit, dtFini, initArray, finiArray } = options.elfMetadata;
      if (entryPoint && entryPoint > 0) {
        const mode = (entryPoint & 1) === 1 ? "MIPS16" : "MIPS32";
        addCandidate(entryPoint, "_start", "ELF_ENTRY", mode);
      }
      if (dtInit && dtInit > 0) {
        const mode = (dtInit & 1) === 1 ? "MIPS16" : "MIPS32";
        addCandidate(dtInit, "_init", "DT_INIT", mode);
      }
      if (dtFini && dtFini > 0) {
        const mode = (dtFini & 1) === 1 ? "MIPS16" : "MIPS32";
        addCandidate(dtFini, "_fini", "DT_FINI", mode);
      }
      if (initArray) {
        for (let i = 0; i < initArray.length; i++) {
          const a = initArray[i]!;
          if (a > 0) {
            const mode = (a & 1) === 1 ? "MIPS16" : "MIPS32";
            addCandidate(a, `init_array_${i}`, "INIT_ARRAY", mode);
          }
        }
      }
      if (finiArray) {
        for (let i = 0; i < finiArray.length; i++) {
          const a = finiArray[i]!;
          if (a > 0) {
            const mode = (a & 1) === 1 ? "MIPS16" : "MIPS32";
            addCandidate(a, `fini_array_${i}`, "FINI_ARRAY", mode);
          }
        }
      }
    }

    // 2. Ingest symbol table entries (.dynsym / .symtab)
    if (options.symbols) {
      for (const sym of options.symbols) {
        if (sym.address > 0) {
          const isMips16 = sym.isMips16 ?? ((sym.address & 1) === 1);
          const mode = isMips16 ? "MIPS16" : "MIPS32";
          const source = sym.isExport ? "EXPORT_SYMBOL" : "LOCAL_SYMBOL";
          addCandidate(sym.address, sym.name, source, mode);
        }
      }
    }

    // 3. Discover direct call targets from instruction stream
    for (const inst of instructions) {
      if (inst.isCall && !inst.isIndirect && inst.targetAddress !== null) {
        const target = inst.targetAddress;
        const normTarget = (target & ~1) >>> 0;
        if (normTarget >= codeStart && normTarget < codeEnd && instMap.has(normTarget)) {
          const targetInst = instMap.get(normTarget)!.inst;
          const isMips16 =
            (target & 1) === 1 ||
            inst.mnemonic === "jal" ||
            targetInst.isaMode === "MIPS16";
          const mode = isMips16 ? "MIPS16" : "MIPS32";
          addCandidate(
            target,
            `sub_0x${normTarget.toString(16)}`,
            "DIRECT_CALL_TARGET",
            mode,
          );
        }
      }
    }

    // 4. Discover function entries via prologue signatures
    for (let i = 0; i < instructions.length; i++) {
      const inst = instructions[i]!;

      // Check whether this position is preceded by a control-flow barrier
      // (unconditional return, unconditional jump/branch, padding, or entry point of binary)
      const prevIsBarrier =
        i === 0 ||
        (i >= 1 &&
          (instructions[i - 1]!.isReturn ||
            (instructions[i - 1]!.isBranch && !instructions[i - 1]!.isConditional) ||
            instructions[i - 1]!.mnemonic === "nop")) ||
        (i >= 2 &&
          instructions[i - 2]!.hasDelaySlot &&
          (instructions[i - 2]!.isReturn ||
            (instructions[i - 2]!.isBranch && !instructions[i - 2]!.isConditional)));

      // MIPS16 save prologue
      if (inst.isaMode === "MIPS16" && inst.mnemonic === "save") {
        if (prevIsBarrier || !candidateMap.has(inst.address)) {
          addCandidate(
            inst.address,
            `sub_0x${inst.address.toString(16)}`,
            "PROLOGUE_SIGNATURE",
            "MIPS16",
          );
        }
        continue;
      }

      // MIPS32 stack frame allocation prologue: addiu $sp, $sp, -imm
      // Only consider as prologue if preceded by a control-flow barrier to avoid chopping internal blocks
      if (prevIsBarrier && inst.isaMode === "MIPS32" && inst.mnemonic === "addiu") {
        const ops = inst.operands.toLowerCase();
        if (ops.startsWith("$sp,$sp,-") || ops.startsWith("$29,$29,-") || ops.startsWith("$sp, $sp, -")) {
          addCandidate(
            inst.address,
            `sub_0x${inst.address.toString(16)}`,
            "PROLOGUE_SIGNATURE",
            "MIPS32",
          );
          continue;
        }
      }

      // MIPS32 PIC setup prologue: lui $gp, ... followed within 2 instructions by addiu $gp, $gp, ...
      if (prevIsBarrier && inst.isaMode === "MIPS32" && inst.mnemonic === "lui" && inst.operands.toLowerCase().startsWith("$gp")) {
        if (i + 1 < instructions.length) {
          const next = instructions[i + 1]!;
          if (next.mnemonic === "addiu" && next.operands.toLowerCase().startsWith("$gp")) {
            addCandidate(
              inst.address,
              `sub_0x${inst.address.toString(16)}`,
              "PROLOGUE_SIGNATURE",
              "MIPS32",
            );
            continue;
          }
        }
      }
    }

    // Sort candidate entries by ascending entry address
    const sortedEntries = Array.from(candidateMap.values()).sort(
      (a, b) => a.address - b.address,
    );

    const recoveredFunctions: RecoveredFunction[] = [];
    let verifiedCount = 0;
    let inferredCount = 0;
    let mips16Count = 0;
    let mips32Count = 0;

    for (let idx = 0; idx < sortedEntries.length; idx++) {
      const entry = sortedEntries[idx]!;
      const nextEntryAddr =
        idx + 1 < sortedEntries.length ? sortedEntries[idx + 1]!.address : codeEnd;

      const entryInfo = instMap.get(entry.address);
      if (!entryInfo) continue;

      const fnInstructions: Instruction[] = [];
      const directCalls: number[] = [];
      const indirectCalls: number[] = [];
      const returns: number[] = [];
      const tailCalls: number[] = [];

      let hasReturn = false;
      let lastInstructionEnd = entry.address;
      let boundaryStatus: FunctionBoundaryStatus = "INFERRED";

      for (let i = entryInfo.index; i < instructions.length; i++) {
        const curInst = instructions[i]!;
        if (curInst.address >= nextEntryAddr) {
          // Reached the entry point of the next function
          break;
        }

        fnInstructions.push(curInst);
        lastInstructionEnd = curInst.address + curInst.size;

        if (curInst.isCall) {
          if (curInst.isIndirect) {
            indirectCalls.push(curInst.address);
          } else if (curInst.targetAddress !== null) {
            directCalls.push(curInst.targetAddress);
          }
        }

        if (curInst.isReturn) {
          returns.push(curInst.address);
          hasReturn = true;

          // If return has a delay slot, include the delay slot instruction
          if (curInst.hasDelaySlot && i + 1 < instructions.length) {
            const delaySlotInst = instructions[i + 1]!;
            if (delaySlotInst.address < nextEntryAddr) {
              fnInstructions.push(delaySlotInst);
              lastInstructionEnd = delaySlotInst.address + delaySlotInst.size;
              i++; // consume delay slot
            }
          }
          boundaryStatus = "VERIFIED";
          break;
        }

        // Tail call check: unconditional jump outside current function bounds or to another function
        if (
          curInst.isBranch &&
          !curInst.isConditional &&
          curInst.targetAddress !== null &&
          (curInst.targetAddress < entry.address || curInst.targetAddress >= nextEntryAddr)
        ) {
          tailCalls.push(curInst.address);
          if (curInst.hasDelaySlot && i + 1 < instructions.length) {
            const delaySlotInst = instructions[i + 1]!;
            if (delaySlotInst.address < nextEntryAddr) {
              fnInstructions.push(delaySlotInst);
              lastInstructionEnd = delaySlotInst.address + delaySlotInst.size;
              i++;
            }
          }
          boundaryStatus = "VERIFIED";
          break;
        }
      }

      if (fnInstructions.length === 0) continue;

      const fnSize = lastInstructionEnd - entry.address;

      // Construct CFG to get basic block count
      const fnCfg = this.cfgBuilder.buildFunctionCfg(fnInstructions, {
        functionName: entry.name,
        entryAddress: entry.address,
        architecture: options.architecture,
      });

      const recovered: RecoveredFunction = {
        name: entry.name,
        entryAddress: entry.address,
        endAddress: lastInstructionEnd,
        size: fnSize,
        isaMode: entry.isaMode,
        entrySource: entry.source,
        boundaryStatus,
        instructionCount: fnInstructions.length,
        basicBlockCount: fnCfg.blocks.size,
        directCalls,
        indirectCalls,
        returns,
        tailCalls,
        hasDelaySlots: entry.isaMode === "MIPS32" || fnInstructions.some((i) => i.hasDelaySlot),
      };

      recoveredFunctions.push(recovered);

      if (boundaryStatus === "VERIFIED") verifiedCount++;
      else inferredCount++;

      if (entry.isaMode === "MIPS16") mips16Count++;
      else mips32Count++;
    }

    return {
      functions: recoveredFunctions,
      totalRecovered: recoveredFunctions.length,
      verifiedBoundariesCount: verifiedCount,
      inferredBoundariesCount: inferredCount,
      mips16FunctionsCount: mips16Count,
      mips32FunctionsCount: mips32Count,
    };
  }
}


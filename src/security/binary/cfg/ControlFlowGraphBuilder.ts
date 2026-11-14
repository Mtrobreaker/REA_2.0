import type {
  Architecture,
  BasicBlock,
  BlockTerminator,
  ControlFlowEdge,
  ControlFlowGraph,
  DecodeOutcome,
  DecodeProvenance,
  DecodeResult,
  FunctionCallEdge,
  Instruction,
  InterproceduralCallGraph,
} from "./types.js";

export interface BuildGraphOptions {
  readonly functionName: string;
  readonly entryAddress: number;
  readonly architecture: Architecture;
  readonly knownFunctions?: ReadonlyMap<number, string>;
  readonly splitOnCalls?: boolean;
}

export class ControlFlowGraphBuilder {
  /**
   * Build an intra-procedural Control-Flow Graph from an array of decoded instructions
   * or a structured DecodeResult.
   */
  public buildFunctionCfg(
    instructionsOrResult: readonly Instruction[] | DecodeResult,
    options: BuildGraphOptions,
  ): ControlFlowGraph {
    let instructions: readonly Instruction[];
    let decodeOutcome: DecodeOutcome | undefined;
    let isComplete = true;
    let decodeError: string | undefined;
    let provenance: DecodeProvenance | undefined;

    if ("outcome" in instructionsOrResult && "instructions" in instructionsOrResult) {
      instructions = instructionsOrResult.instructions;
      decodeOutcome = instructionsOrResult.outcome;
      provenance = instructionsOrResult.provenance;
      decodeError = instructionsOrResult.error?.message ?? instructionsOrResult.haltReason;
      isComplete = instructionsOrResult.outcome === "SUCCESS";
    } else {
      instructions = instructionsOrResult;
      if (instructions.length === 0) {
        decodeOutcome = "FAILED";
        isComplete = false;
        decodeError = "Empty instruction stream or decoder failure";
      } else if (instructions.some((i) => i.isMalformed === true)) {
        decodeOutcome = "PARTIAL";
        isComplete = false;
      } else {
        decodeOutcome = "SUCCESS";
        isComplete = true;
      }
    }

    if (instructions.length === 0) {
      return {
        functionName: options.functionName,
        entryBlockId: `bb_0x${options.entryAddress.toString(16)}`,
        blocks: new Map(),
        edges: [],
        architecture: options.architecture,
        decodeOutcome: decodeOutcome ?? "FAILED",
        isComplete: false,
        decodeError: decodeError ?? "Empty instruction stream or decoder failure",
        provenance,
      };
    }

    const addrToInstIndex = new Map<number, number>();
    instructions.forEach((inst, idx) => {
      addrToInstIndex.set(inst.address, idx);
    });

    const isMips = options.architecture === "MIPS";

    // 1. Identify Leaders
    const leaderIndices = new Set<number>();
    leaderIndices.add(0); // Function entry point is always a leader

    for (let i = 0; i < instructions.length; i++) {
      const inst = instructions[i]!;

      const shouldSplitOnCall = (options.splitOnCalls ?? true) && inst.isCall;
      if (inst.isBranch || shouldSplitOnCall) {
        // Target of jump/call (if internal) is a leader
        const normTarget =
          inst.targetAddress !== null ? (inst.targetAddress & ~1) >>> 0 : null;
        if (normTarget !== null && addrToInstIndex.has(normTarget)) {
          leaderIndices.add(addrToInstIndex.get(normTarget)!);
        }

        const hasDelay =
          inst.hasDelaySlot ?? (isMips && inst.isaMode !== "MIPS16");
        if (hasDelay) {
          // Delay slot instruction executes with the jump/call; leader starts at i + 2
          if (i + 2 < instructions.length) {
            leaderIndices.add(i + 2);
          }
        } else {
          // Non-delay instruction: leader begins at i + 1
          if (i + 1 < instructions.length) {
            leaderIndices.add(i + 1);
          }
        }
      } else if (inst.isReturn) {
        const hasDelay =
          inst.hasDelaySlot ?? (isMips && inst.isaMode !== "MIPS16");
        if (hasDelay) {
          if (i + 2 < instructions.length) {
            leaderIndices.add(i + 2);
          }
        } else {
          if (i + 1 < instructions.length) {
            leaderIndices.add(i + 1);
          }
        }
      }
    }

    const sortedLeaders = Array.from(leaderIndices).sort((a, b) => a - b);

    // 2. Partition Instructions into Basic Blocks
    const blockList: BasicBlock[] = [];
    const blockMap = new Map<string, BasicBlock>();
    const addrToBlockId = new Map<number, string>();

    for (let l = 0; l < sortedLeaders.length; l++) {
      const startIdx = sortedLeaders[l]!;
      const endIdx = l + 1 < sortedLeaders.length ? sortedLeaders[l + 1]! : instructions.length;
      const blockInsts = instructions.slice(startIdx, endIdx);
      if (blockInsts.length === 0) continue;

      const firstInst = blockInsts[0]!;
      const lastInst = blockInsts[blockInsts.length - 1]!;
      const blockId = `bb_0x${firstInst.address.toString(16)}`;

      // Check if block ends with a delay-slot pair
      let controlInst = lastInst;
      let hasMissingDelaySlot = false;

      if (blockInsts.length >= 2) {
        const candidateControl = blockInsts[blockInsts.length - 2]!;
        const candHasDelay =
          candidateControl.hasDelaySlot ??
          (isMips && candidateControl.isaMode !== "MIPS16");
        if (
          candHasDelay &&
          (candidateControl.isBranch ||
            candidateControl.isCall ||
            candidateControl.isReturn)
        ) {
          controlInst = candidateControl;
        }
      }

      const lastHasDelay =
        lastInst.hasDelaySlot ?? (isMips && lastInst.isaMode !== "MIPS16");
      if (
        lastHasDelay &&
        (lastInst.isBranch || lastInst.isCall || lastInst.isReturn)
      ) {
        // Controlling instruction is at the end of block without delay slot -> truncated delay slot!
        hasMissingDelaySlot = true;
      }

      let terminatorType: BlockTerminator = "fallthrough";
      const hasMalformed = blockInsts.some((i) => i.isMalformed === true) || hasMissingDelaySlot;

      if (hasMalformed) {
        terminatorType = "halt";
      } else if (controlInst.isReturn) {
        terminatorType = "return";
      } else if (controlInst.isIndirect) {
        terminatorType = "indirect";
      } else if (controlInst.isConditional && controlInst.isBranch) {
        terminatorType = "conditional_branch";
      } else if (controlInst.isBranch) {
        terminatorType = "branch";
      } else if (controlInst.isCall) {
        terminatorType = "call";
      }

      const block: BasicBlock = {
        id: blockId,
        startAddress: firstInst.address,
        endAddress: lastInst.address + lastInst.size,
        functionName: options.functionName,
        instructions: blockInsts,
        predecessorIds: [],
        successorIds: [],
        terminatorType,
      };

      blockList.push(block);
      blockMap.set(blockId, block);
      addrToBlockId.set(firstInst.address, blockId);
    }

    // 3. Connect Control-Flow Edges
    const edges: ControlFlowEdge[] = [];
    const predecessors = new Map<string, Set<string>>();
    const successors = new Map<string, Set<string>>();

    for (const b of blockList) {
      predecessors.set(b.id, new Set());
      successors.set(b.id, new Set());
    }

    for (let bIdx = 0; bIdx < blockList.length; bIdx++) {
      const currentBlock = blockList[bIdx]!;
      let controlInst = currentBlock.instructions[currentBlock.instructions.length - 1]!;
      if (currentBlock.instructions.length >= 2) {
        const candidateControl =
          currentBlock.instructions[currentBlock.instructions.length - 2]!;
        const candHasDelay =
          candidateControl.hasDelaySlot ??
          (isMips && candidateControl.isaMode !== "MIPS16");
        if (
          candHasDelay &&
          (candidateControl.isBranch ||
            candidateControl.isCall ||
            candidateControl.isReturn)
        ) {
          controlInst = candidateControl;
        }
      }
      const nextBlock = bIdx + 1 < blockList.length ? blockList[bIdx + 1] : undefined;

      const addEdge = (toBlockId: string, type: ControlFlowEdge["type"], cond?: string) => {
        edges.push({
          fromBlockId: currentBlock.id,
          toBlockId,
          type,
          ...(cond ? { condition: cond } : {}),
        });
        successors.get(currentBlock.id)?.add(toBlockId);
        predecessors.get(toBlockId)?.add(currentBlock.id);
      };

      if (currentBlock.terminatorType === "halt") {
        // Halted block (malformed instruction, missing delay slot, or trap): fail closed with no outgoing edges
        continue;
      }

      if (controlInst.isReturn) {
        // No intra-procedural successor
        continue;
      }

      const targetAddrNorm =
        controlInst.targetAddress !== null
          ? (controlInst.targetAddress & ~1) >>> 0
          : null;

      if (controlInst.isBranch && !controlInst.isConditional) {
        // Direct jump: only target block is successor
        if (targetAddrNorm !== null && addrToBlockId.has(targetAddrNorm)) {
          addEdge(addrToBlockId.get(targetAddrNorm)!, "jump");
        }
        continue;
      }

      if (controlInst.isConditional && controlInst.isBranch) {
        // Branch taken edge
        if (targetAddrNorm !== null && addrToBlockId.has(targetAddrNorm)) {
          addEdge(
            addrToBlockId.get(targetAddrNorm)!,
            "true_branch",
            controlInst.mnemonic,
          );
        }
        // Fallthrough edge (instruction following delay slot or compact branch)
        if (nextBlock) {
          addEdge(nextBlock.id, "false_branch", `!(${controlInst.mnemonic})`);
        }
        continue;
      }

      if (controlInst.isCall) {
        // Calls fall through to next block after callee returns
        if (nextBlock) {
          addEdge(nextBlock.id, "fallthrough");
        }
        continue;
      }

      // Default fallthrough to adjacent sequential block
      if (nextBlock) {
        addEdge(nextBlock.id, "fallthrough");
      }
    }

    // 4. Update blocks with predecessors and successors
    const finalizedBlocks = new Map<string, BasicBlock>();
    for (const b of blockList) {
      finalizedBlocks.set(b.id, {
        ...b,
        predecessorIds: Array.from(predecessors.get(b.id) ?? []),
        successorIds: Array.from(successors.get(b.id) ?? []),
      });
    }

    const hasAnyHaltedBlock = blockList.some((b) => b.terminatorType === "halt");
    const finalIsComplete = isComplete && !hasAnyHaltedBlock;
    const finalOutcome: DecodeOutcome = finalIsComplete
      ? "SUCCESS"
      : (decodeOutcome ?? (hasAnyHaltedBlock ? "PARTIAL" : "SUCCESS"));

    const entryBlockId = `bb_0x${instructions[0]!.address.toString(16)}`;

    return {
      functionName: options.functionName,
      entryBlockId,
      blocks: finalizedBlocks,
      edges,
      architecture: options.architecture,
      decodeOutcome: finalOutcome,
      isComplete: finalIsComplete,
      decodeError,
      provenance,
    };
  }

  /**
   * Build an Interprocedural Call Graph across discovered functions and external API calls.
   */
  public buildCallGraph(
    functions: ReadonlyMap<string, ControlFlowGraph>,
    knownSymbols: ReadonlyMap<number, string>,
    entryPoints: readonly string[] = ["main", "_start"],
  ): InterproceduralCallGraph {
    const callEdges: FunctionCallEdge[] = [];
    const functionNames = Array.from(functions.keys());

    for (const [callerName, cfg] of functions.entries()) {
      if (cfg.decodeOutcome === "UNSUPPORTED" || cfg.decodeOutcome === "FAILED") {
        // Do not extract call edges from failed or unsupported CFGs
        continue;
      }
      for (const block of cfg.blocks.values()) {
        if (block.terminatorType === "halt") {
          // Do not extract call edges from halted / malformed blocks
          continue;
        }
        for (const inst of block.instructions) {
          if (inst.isMalformed) continue;

          // Check for call instruction or unconditional cross-function branch (tail-call optimization)
          const isCrossFunctionBranch =
            inst.isBranch &&
            !inst.isConditional &&
            inst.targetAddress !== null &&
            !Array.from(cfg.blocks.values()).some(
              (b) => inst.targetAddress! >= b.startAddress && inst.targetAddress! < b.endAddress,
            );

          if (inst.isCall || isCrossFunctionBranch) {
            let callee = "unknown_indirect";
            if (inst.targetAddress !== null) {
              callee = knownSymbols.get(inst.targetAddress) ?? `sub_0x${inst.targetAddress.toString(16)}`;
            }
            callEdges.push({
              callerFunction: callerName,
              callerAddress: inst.address,
              calleeFunction: callee,
              calleeAddress: inst.targetAddress,
              isIndirect: inst.isIndirect,
            });
          }
        }
      }
    }

    return {
      functions: functionNames,
      edges: callEdges,
      entryPoints,
    };
  }
}


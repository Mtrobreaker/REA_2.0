import type {
  ControlFlowGraph,
  FunctionCallEdge,
  InterproceduralCallGraph,
  ReachabilityAnalysisResult,
  ReachabilityPath,
  ReachabilityStep,
} from "./types.js";

export interface ReachabilityOptions {
  readonly entryPoints?: readonly string[];
  readonly maxPathDepth?: number;
  readonly maxPaths?: number;
}

export class ReachabilityAnalyzer {
  /**
   * Analyze reachability from entry points to a target function or API sink.
   */
  public analyzeReachability(
    targetName: string,
    callGraph: InterproceduralCallGraph,
    cfgs: ReadonlyMap<string, ControlFlowGraph>,
    options?: ReachabilityOptions,
  ): ReachabilityAnalysisResult {
    const entryPoints = options?.entryPoints ?? callGraph.entryPoints;
    const maxDepth = options?.maxPathDepth ?? 15;
    const maxPaths = options?.maxPaths ?? 5;

    // Check for target CFG existence and completion
    const targetCfg = cfgs.get(targetName);
    const allCfgs = Array.from(cfgs.values());
    const primaryProvenance = targetCfg?.provenance ?? (allCfgs.length > 0 ? allCfgs[0]?.provenance : undefined);
    const isExternalSink = !targetCfg && callGraph.edges.some((e) => e.calleeFunction === targetName);

    const isTargetMissingOrFailed =
      !isExternalSink &&
      (!targetCfg ||
        targetCfg.blocks.size === 0 ||
        targetCfg.decodeOutcome === "UNSUPPORTED" ||
        targetCfg.decodeOutcome === "FAILED" ||
        targetCfg.decodeOutcome === "MALFORMED" ||
        cfgs.size === 0);

    if (isTargetMissingOrFailed) {
      return {
        status: "INCONCLUSIVE",
        paths: [],
        entryPoint: entryPoints.join(", "),
        target: targetName,
        deadCodeFunctions: [],
        reasoning: `Reachability analysis inconclusive: target '${targetName}' has missing, empty, or failed CFG (outcome: ${targetCfg?.decodeOutcome ?? "FAILED"}).`,
        provider: "ReaControlFlowEngine",
        provenance: primaryProvenance,
        analysisOutcome: targetCfg?.decodeOutcome ?? "FAILED",
        isComplete: false,
      };
    }

    if (entryPoints.length === 0) {
      return {
        status: "INCONCLUSIVE",
        paths: [],
        entryPoint: "",
        target: targetName,
        deadCodeFunctions: [],
        reasoning: `Reachability analysis inconclusive: no entry points provided.`,
        provider: "ReaControlFlowEngine",
        provenance: primaryProvenance,
        analysisOutcome: "FAILED",
        isComplete: false,
      };
    }

    // Find all call paths from any entry point to targetName in CallGraph
    const discoveredPaths: ReachabilityPath[] = [];
    const unresolvedIndirectJumps: number[] = [];

    // Map callers to outgoing edges
    const outgoingEdges = new Map<string, FunctionCallEdge[]>();
    for (const edge of callGraph.edges) {
      const list = outgoingEdges.get(edge.callerFunction) ?? [];
      list.push(edge);
      outgoingEdges.set(edge.callerFunction, list);
    }

    // Traverse paths from each entry point
    for (const entry of entryPoints) {
      if (entry === targetName) {
        discoveredPaths.push({
          source: entry,
          target: targetName,
          steps: [
            {
              functionName: entry,
              blockId: cfgs.get(entry)?.entryBlockId ?? "entry",
              address: 0,
              description: `Target is direct entry point: ${entry}`,
            },
          ],
          isDefinitive: true,
          unresolvedIndirectJumps: [],
        });
        continue;
      }

      const queue: {
        currentFn: string;
        path: typeof callGraph.edges;
        visited: Set<string>;
      }[] = [
        {
          currentFn: entry,
          path: [],
          visited: new Set([entry]),
        },
      ];

      while (queue.length > 0 && discoveredPaths.length < maxPaths) {
        const item = queue.shift()!;
        if (item.path.length >= maxDepth) continue;

        const edges = outgoingEdges.get(item.currentFn) ?? [];
        for (const edge of edges) {
          if (edge.calleeFunction === targetName) {
            // Found a reaching call path!
            const fullEdges = [...item.path, edge];
            const steps: ReachabilityStep[] = [
              {
                functionName: entry,
                blockId: cfgs.get(entry)?.entryBlockId ?? "entry",
                address: fullEdges[0]?.callerAddress ?? 0,
                description: `Entry point '${entry}'`,
              },
            ];

            let isDefinitive = true;
            const pathIndirects: number[] = [];

            for (const stepEdge of fullEdges) {
              if (stepEdge.isIndirect) {
                isDefinitive = false;
                pathIndirects.push(stepEdge.callerAddress);
                unresolvedIndirectJumps.push(stepEdge.callerAddress);
              }
              steps.push({
                functionName: stepEdge.calleeFunction,
                blockId: `call_0x${stepEdge.callerAddress.toString(16)}`,
                address: stepEdge.callerAddress,
                description: `Calls '${stepEdge.calleeFunction}' at 0x${stepEdge.callerAddress.toString(16)}${stepEdge.isIndirect ? " (indirect)" : ""}`,
              });
            }

            discoveredPaths.push({
              source: entry,
              target: targetName,
              steps,
              isDefinitive,
              unresolvedIndirectJumps: pathIndirects,
            });

            if (discoveredPaths.length >= maxPaths) break;
          } else if (
            !item.visited.has(edge.calleeFunction) &&
            cfgs.has(edge.calleeFunction)
          ) {
            const nextVisited = new Set(item.visited);
            nextVisited.add(edge.calleeFunction);
            queue.push({
              currentFn: edge.calleeFunction,
              path: [...item.path, edge],
              visited: nextVisited,
            });
          }
        }
      }
    }

    // Identify dead code functions
    const reachableFunctions = new Set<string>();
    const entryQueue = [...entryPoints];
    while (entryQueue.length > 0) {
      const fn = entryQueue.shift()!;
      if (reachableFunctions.has(fn)) continue;
      reachableFunctions.add(fn);

      const edges = outgoingEdges.get(fn) ?? [];
      for (const e of edges) {
        if (!reachableFunctions.has(e.calleeFunction)) {
          entryQueue.push(e.calleeFunction);
        }
      }
    }

    const deadCodeFunctions = callGraph.functions.filter(
      (fn) => !reachableFunctions.has(fn) && !entryPoints.includes(fn),
    );

    // Determine status
    if (discoveredPaths.length === 0) {
      // Check if target is genuinely in dead code of a complete, successfully analyzed graph
      const anyIncompleteCfg = allCfgs.some(
        (c) => c.isComplete === false || c.decodeOutcome !== "SUCCESS",
      );
      const targetInCallGraph = callGraph.functions.includes(targetName);
      const isTargetComplete = targetCfg ? targetCfg.isComplete === true && targetCfg.decodeOutcome === "SUCCESS" : true;

      if ((!targetInCallGraph && !isExternalSink) || anyIncompleteCfg || !isTargetComplete) {
        return {
          status: "INCONCLUSIVE",
          paths: [],
          entryPoint: entryPoints.join(", "),
          target: targetName,
          deadCodeFunctions,
          reasoning: `No call path discovered from entry points to '${targetName}', but CFG or call graph is incomplete (contains partial, malformed, or unanalyzed regions). Reachability cannot be definitively disproven.`,
          provider: "ReaControlFlowEngine",
          provenance: primaryProvenance,
          analysisOutcome: targetCfg ? (targetCfg.decodeOutcome === "SUCCESS" ? "PARTIAL" : targetCfg.decodeOutcome) : "PARTIAL",
          isComplete: false,
        };
      }

      // Fail closed if any reachable function contains unresolved indirect calls, indirect branches, or dynamic dispatch sites
      const hasUnresolvedDynamicDispatch = Array.from(reachableFunctions).some((fn) => {
        const edges = outgoingEdges.get(fn) ?? [];
        if (edges.some((e) => e.isIndirect || e.calleeFunction === "unknown_indirect")) {
          return true;
        }
        const cfg = cfgs.get(fn);
        if (cfg) {
          return Array.from(cfg.blocks.values()).some(
            (b) => b.terminatorType === "indirect" || b.instructions.some((i) => i.isIndirect),
          );
        }
        return false;
      });

      if (hasUnresolvedDynamicDispatch) {
        return {
          status: "INCONCLUSIVE",
          paths: [],
          entryPoint: entryPoints.join(", "),
          target: targetName,
          deadCodeFunctions,
          reasoning: `No direct call path discovered from entry points to '${targetName}', but reachable code contains unresolved indirect calls, function pointers, or dynamic branch sites. Dynamic target resolution is required to soundly rule out reachability.`,
          provider: "ReaControlFlowEngine",
          provenance: primaryProvenance,
          analysisOutcome: "PARTIAL",
          isComplete: false,
        };
      }

      // Conclusive UNREACHABLE: all evaluated CFGs are complete, uncorrupted, and free of unresolved dynamic dispatch
      return {
        status: "UNREACHABLE",
        paths: [],
        entryPoint: entryPoints.join(", "),
        target: targetName,
        deadCodeFunctions,
        reasoning: `No call path discovered from entry points [${entryPoints.join(", ")}] to sink '${targetName}'. Target is proven dead or uncalled code in complete CFG.`,
        provider: "ReaControlFlowEngine",
        provenance: primaryProvenance,
        analysisOutcome: "SUCCESS",
        isComplete: true,
      };
    }

    const definitivePaths = discoveredPaths.filter((p) => p.isDefinitive);
    if (definitivePaths.length > 0) {
      return {
        status: "REACHABLE",
        paths: discoveredPaths,
        entryPoint: entryPoints.join(", "),
        target: targetName,
        deadCodeFunctions,
        reasoning: `Proven reachability path from entry point '${definitivePaths[0]!.source}' to sink '${targetName}' along ${definitivePaths[0]!.steps.length} call stages.`,
        provider: "ReaControlFlowEngine",
        provenance: primaryProvenance,
        analysisOutcome: "SUCCESS",
        isComplete: true,
      };
    }

    return {
      status: "INCONCLUSIVE",
      paths: discoveredPaths,
      entryPoint: entryPoints.join(", "),
      target: targetName,
      deadCodeFunctions,
      reasoning: `Potential path exists from '${discoveredPaths[0]!.source}' to '${targetName}', but traverses ${unresolvedIndirectJumps.length} unresolved indirect call sites. Reachability cannot be definitively proven.`,
      provider: "ReaControlFlowEngine",
      provenance: primaryProvenance,
      analysisOutcome: "PARTIAL",
      isComplete: false,
    };
  }
}

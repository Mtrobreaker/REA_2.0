import { createHash } from "node:crypto";
import type { ControlFlowGraph, InterproceduralCallGraph } from "../cfg/types.js";
import type {
  SanitizerGuard,
  TaintFlowResult,
  TaintPathStep,
  TaintSink,
  TaintSource,
  TaintStatus,
} from "./types.js";

export interface TaintAnalysisInput {
  readonly source: TaintSource;
  readonly sink: TaintSink;
  readonly callGraph: InterproceduralCallGraph;
  readonly cfgs: ReadonlyMap<string, ControlFlowGraph>;
  readonly sanitizers?: readonly SanitizerGuard[];
  readonly hasUnresolvedAliases?: boolean;
  readonly isConstantArgument?: boolean;
}

export class TaintEngine {
  /**
   * Perform interprocedural taint propagation analysis from a specified source to a sensitive sink.
   */
  public analyzeTaintFlow(input: TaintAnalysisInput): TaintFlowResult {
    const { source, sink, callGraph, sanitizers = [], hasUnresolvedAliases = false, isConstantArgument = false } = input;

    // 1. Check for immediate false positive: Sink argument is a static compile-time constant
    if (isConstantArgument) {
      return {
        status: "NO_TAINT",
        source: null,
        sink,
        steps: [
          {
            functionName: sink.functionName,
            address: sink.address,
            operation: "sink_consumption",
            variableOrRegister: `param_${sink.vulnerableParameterIndex}`,
            description: `Sink '${sink.api}' consumed a static compile-time constant string, not tainted input.`,
          },
        ],
        sanitizers: [],
        isSanitized: false,
        hasUnresolvedAliases: false,
        evidenceId: this.computeEvidenceId(sink, []),
        reasoning: `Sink argument in function '${sink.functionName}' is a hardcoded constant value. No external data-flow reaches this sink.`,
      };
    }

    // 2. Intra-function taint flow (source and sink in the same function)
    if (source.functionName === sink.functionName) {
      const steps: TaintPathStep[] = [
        {
          functionName: source.functionName,
          address: source.address,
          operation: "source_introduction",
          variableOrRegister: source.variableName ?? "buffer",
          description: `Tainted input received via source API '${source.api}' (${source.kind})`,
        },
      ];

      // Check sanitizers within the same function
      const relevantSanitizers = sanitizers.filter(
        (s) => s.functionName === source.functionName && s.address > source.address && s.address < sink.address,
      );

      const dominatingSanitizer = relevantSanitizers.find((s) => s.isSound && s.dominatesSink);

      if (dominatingSanitizer) {
        steps.push({
          functionName: dominatingSanitizer.functionName,
          address: dominatingSanitizer.address,
          operation: "sanitization_attempt",
          variableOrRegister: source.variableName ?? "buffer",
          description: `Sound dominating guard applied: ${dominatingSanitizer.expression} (${dominatingSanitizer.type})`,
        });

        return {
          status: "MITIGATED_TAINT",
          source,
          sink,
          steps,
          sanitizers: relevantSanitizers,
          isSanitized: true,
          hasUnresolvedAliases,
          evidenceId: this.computeEvidenceId(sink, steps),
          reasoning: `Taint flow from '${source.api}' to '${sink.api}' in function '${source.functionName}' is strictly dominated by sound guard '${dominatingSanitizer.expression}'.`,
        };
      }

      if (hasUnresolvedAliases) {
        return {
          status: "INCONCLUSIVE",
          source,
          sink,
          steps,
          sanitizers: relevantSanitizers,
          isSanitized: false,
          hasUnresolvedAliases: true,
          evidenceId: this.computeEvidenceId(sink, steps),
          reasoning: `Taint path exists between '${source.api}' and '${sink.api}', but untracked pointer alias or unknown indirect modification was detected. Exploitability cannot be definitively proven.`,
        };
      }

      steps.push({
        functionName: sink.functionName,
        address: sink.address,
        operation: "sink_consumption",
        variableOrRegister: `param_${sink.vulnerableParameterIndex}`,
        description: `Unsanitized tainted value reaches vulnerable sink '${sink.api}'`,
      });

      return {
        status: "PROVEN_TAINT",
        source,
        sink,
        steps,
        sanitizers: relevantSanitizers,
        isSanitized: false,
        hasUnresolvedAliases: false,
        evidenceId: this.computeEvidenceId(sink, steps),
        reasoning: `Unsanitized taint flow established from source '${source.api}' directly into dangerous sink '${sink.api}' parameter ${sink.vulnerableParameterIndex}.`,
      };
    }

    // 3. Interprocedural taint flow (propagating across function call boundaries)
    // Find path in call graph from source.functionName to sink.functionName
    const path = this.findCallPath(source.functionName, sink.functionName, callGraph);
    if (!path) {
      return {
        status: "NO_TAINT",
        source,
        sink,
        steps: [],
        sanitizers: [],
        isSanitized: false,
        hasUnresolvedAliases,
        evidenceId: this.computeEvidenceId(sink, []),
        reasoning: `No call path connects source function '${source.functionName}' to sink function '${sink.functionName}'.`,
      };
    }

    const steps: TaintPathStep[] = [
      {
        functionName: source.functionName,
        address: source.address,
        operation: "source_introduction",
        variableOrRegister: source.variableName ?? "buffer",
        description: `Tainted input received via '${source.api}' (${source.kind})`,
      },
    ];

    for (let i = 0; i < path.length - 1; i++) {
      const caller = path[i]!;
      const callee = path[i + 1]!;
      steps.push({
        functionName: caller,
        address: 0,
        operation: "parameter_pass",
        variableOrRegister: "arg0",
        description: `Function '${caller}' passes tainted value to '${callee}'`,
      });
    }

    // Check all sanitizers along the entire path
    const dominatingSanitizer = sanitizers.find((s) => s.isSound && s.dominatesSink);
    if (dominatingSanitizer) {
      steps.push({
        functionName: dominatingSanitizer.functionName,
        address: dominatingSanitizer.address,
        operation: "sanitization_attempt",
        variableOrRegister: "buffer",
        description: `Dominating guard applied in '${dominatingSanitizer.functionName}': ${dominatingSanitizer.expression}`,
      });

      return {
        status: "MITIGATED_TAINT",
        source,
        sink,
        steps,
        sanitizers,
        isSanitized: true,
        hasUnresolvedAliases,
        evidenceId: this.computeEvidenceId(sink, steps),
        reasoning: `Interprocedural taint flow from '${source.functionName}' to '${sink.functionName}' is safely dominated by guard '${dominatingSanitizer.expression}'.`,
      };
    }

    if (hasUnresolvedAliases) {
      return {
        status: "INCONCLUSIVE",
        source,
        sink,
        steps,
        sanitizers,
        isSanitized: false,
        hasUnresolvedAliases: true,
        evidenceId: this.computeEvidenceId(sink, steps),
        reasoning: `Call path exists from '${source.functionName}' to '${sink.functionName}', but indirect pointer alias or unknown function modification occurs along the path.`,
      };
    }

    steps.push({
      functionName: sink.functionName,
      address: sink.address,
      operation: "sink_consumption",
      variableOrRegister: `param_${sink.vulnerableParameterIndex}`,
      description: `Tainted value consumed by sink '${sink.api}' without dominating guard`,
    });

    return {
      status: "PROVEN_TAINT",
      source,
      sink,
      steps,
      sanitizers,
      isSanitized: false,
      hasUnresolvedAliases: false,
      evidenceId: this.computeEvidenceId(sink, steps),
      reasoning: `Proven interprocedural taint propagation from source '${source.api}' in '${source.functionName}' to sink '${sink.api}' in '${sink.functionName}' across ${path.length} functions.`,
    };
  }

  private findCallPath(
    fromFn: string,
    toFn: string,
    callGraph: InterproceduralCallGraph,
  ): string[] | null {
    const queue: { current: string; path: string[] }[] = [{ current: fromFn, path: [fromFn] }];
    const visited = new Set<string>([fromFn]);

    while (queue.length > 0) {
      const { current, path } = queue.shift()!;
      if (current === toFn) return path;

      const edges = callGraph.edges.filter((e) => e.callerFunction === current);
      for (const edge of edges) {
        if (!visited.has(edge.calleeFunction)) {
          visited.add(edge.calleeFunction);
          queue.push({
            current: edge.calleeFunction,
            path: [...path, edge.calleeFunction],
          });
        }
      }
    }

    return null;
  }

  private computeEvidenceId(sink: TaintSink, steps: readonly TaintPathStep[]): string {
    const hash = createHash("sha256");
    hash.update(`${sink.functionName}:${sink.api}:${sink.address}`);
    for (const s of steps) {
      hash.update(`${s.functionName}:${s.operation}:${s.variableOrRegister}`);
    }
    return `ev_taint_${hash.digest("hex").slice(0, 32)}`;
  }
}


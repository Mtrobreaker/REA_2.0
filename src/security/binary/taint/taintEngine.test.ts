import { describe, expect, it } from "vitest";
import { TaintEngine } from "./TaintEngine.js";
import type { TaintSink, TaintSource } from "./types.js";
import type { InterproceduralCallGraph } from "../cfg/types.js";

describe("Phase 7B: Intra & Inter-procedural Taint Flow Verification", () => {
  const engine = new TaintEngine();

  const emptyCallGraph: InterproceduralCallGraph = {
    functions: ["process_request"],
    edges: [],
    entryPoints: ["process_request"],
  };

  it("proves taint flow from socket recv directly into system() within a function", () => {
    const source: TaintSource = {
      kind: "network_socket",
      api: "recv",
      functionName: "process_request",
      address: 0x1000,
      targetParameterOrReturn: 1,
      variableName: "packet_buf",
    };

    const sink: TaintSink = {
      api: "system",
      functionName: "process_request",
      address: 0x1050,
      vulnerableParameterIndex: 0,
    };

    const res = engine.analyzeTaintFlow({
      source,
      sink,
      callGraph: emptyCallGraph,
      cfgs: new Map(),
    });

    expect(res.status).toBe("PROVEN_TAINT");
    expect(res.isSanitized).toBe(false);
    expect(res.evidenceId).toMatch(/^ev_taint_/u);
    expect(res.steps.length).toBe(2);
    expect(res.reasoning).toContain("Unsanitized taint flow established");
  });

  it("mitigates taint when a sound dominating guard is verified along the path", () => {
    const source: TaintSource = {
      kind: "environment_variable",
      api: "getenv",
      functionName: "read_config",
      address: 0x2000,
      targetParameterOrReturn: "return",
      variableName: "env_val",
    };

    const sink: TaintSink = {
      api: "strcpy",
      functionName: "read_config",
      address: 0x2080,
      vulnerableParameterIndex: 1,
    };

    const res = engine.analyzeTaintFlow({
      source,
      sink,
      callGraph: emptyCallGraph,
      cfgs: new Map(),
      sanitizers: [
        {
          functionName: "read_config",
          address: 0x2040,
          type: "bounds_check",
          expression: "strlen(env_val) < sizeof(dest)",
          isSound: true,
          dominatesSink: true,
        },
      ],
    });

    expect(res.status).toBe("MITIGATED_TAINT");
    expect(res.isSanitized).toBe(true);
    expect(res.sanitizers.length).toBe(1);
    expect(res.reasoning).toContain("dominated by sound guard");
  });

  it("suppresses finding (NO_TAINT) when sink consumes a compile-time constant string", () => {
    const source: TaintSource = {
      kind: "network_socket",
      api: "recv",
      functionName: "server_init",
      address: 0x3000,
      targetParameterOrReturn: 1,
    };

    const sink: TaintSink = {
      api: "system",
      functionName: "server_init",
      address: 0x3050,
      vulnerableParameterIndex: 0,
    };

    // Sink consumes constant string e.g. system("/sbin/iptables -F")
    const res = engine.analyzeTaintFlow({
      source,
      sink,
      callGraph: emptyCallGraph,
      cfgs: new Map(),
      isConstantArgument: true,
    });

    expect(res.status).toBe("NO_TAINT");
    expect(res.source).toBeNull();
    expect(res.reasoning).toContain("hardcoded constant value");
  });
});

describe("Phase 7B: Interprocedural Call Propagation & Alias Handling", () => {
  const engine = new TaintEngine();

  it("propagates taint across multi-hop interprocedural function calls", () => {
    // recv_packet (source) -> dispatch_handler -> execute_ping (sink)
    const callGraph: InterproceduralCallGraph = {
      functions: ["recv_packet", "dispatch_handler", "execute_ping"],
      edges: [
        {
          callerFunction: "recv_packet",
          callerAddress: 0x1040,
          calleeFunction: "dispatch_handler",
          calleeAddress: 0x2000,
          isIndirect: false,
        },
        {
          callerFunction: "dispatch_handler",
          callerAddress: 0x2040,
          calleeFunction: "execute_ping",
          calleeAddress: 0x3000,
          isIndirect: false,
        },
      ],
      entryPoints: ["recv_packet"],
    };

    const source: TaintSource = {
      kind: "network_socket",
      api: "recv",
      functionName: "recv_packet",
      address: 0x1010,
      targetParameterOrReturn: 1,
    };

    const sink: TaintSink = {
      api: "system",
      functionName: "execute_ping",
      address: 0x3080,
      vulnerableParameterIndex: 0,
    };

    const res = engine.analyzeTaintFlow({
      source,
      sink,
      callGraph,
      cfgs: new Map(),
    });

    expect(res.status).toBe("PROVEN_TAINT");
    expect(res.steps.length).toBe(4);
    expect(res.reasoning).toContain("across 3 functions");
  });

  it("evaluates to INCONCLUSIVE when unresolved pointer alias interferes with flow", () => {
    const source: TaintSource = {
      kind: "command_line",
      api: "argv",
      functionName: "main",
      address: 0x1000,
      targetParameterOrReturn: 1,
    };

    const sink: TaintSink = {
      api: "strcpy",
      functionName: "main",
      address: 0x1050,
      vulnerableParameterIndex: 1,
    };

    const res = engine.analyzeTaintFlow({
      source,
      sink,
      callGraph: { functions: ["main"], edges: [], entryPoints: ["main"] },
      cfgs: new Map(),
      hasUnresolvedAliases: true,
    });

    expect(res.status).toBe("INCONCLUSIVE");
    expect(res.hasUnresolvedAliases).toBe(true);
    expect(res.reasoning).toContain("untracked pointer alias");
  });
});


import { describe, expect, it } from "vitest";
import { WitnessGenerator } from "./WitnessGenerator.js";
import { WitnessValidator } from "./WitnessValidator.js";
import type { TaintSink, TaintSource } from "../taint/types.js";

describe("Phase 7C: Witness Generation & Stable Digest Derivation", () => {
  const generator = new WitnessGenerator();

  const source: TaintSource = {
    kind: "network_socket",
    api: "recv",
    functionName: "handle_client",
    address: 0x1000,
    targetParameterOrReturn: 1,
  };

  const sink: TaintSink = {
    api: "system",
    functionName: "exec_action",
    address: 0x2050,
    vulnerableParameterIndex: 0,
  };

  it("synthesizes canonical witness artifact for command injection with stable digest", () => {
    const witness = generator.generateWitness({
      findingId: "fnd_test_cmd_injection_001",
      ruleId: "REA-VULN-002-COMMAND-INJECTION",
      category: "command_injection",
      source,
      sink,
    });

    expect(witness.witnessId).toMatch(/^wit_[a-f0-9]{32}$/u);
    expect(witness.artifactDigest.length).toBe(64);
    expect(witness.constraints.length).toBeGreaterThanOrEqual(2);

    const delimConstraint = witness.constraints.find((c) => c.type === "character_present");
    expect(delimConstraint).toBeDefined();
    expect(delimConstraint?.expectedValue).toContain(";");

    expect(witness.environment.architecture).toBe("ARM");
    expect(witness.environment.mode).toBe("simulated_harness");
  });

  it("derives exact overflow constraints for unsafe memory copies", () => {
    const memSink: TaintSink = {
      api: "strcpy",
      functionName: "parse_header",
      address: 0x3010,
      vulnerableParameterIndex: 1,
    };

    const witness = generator.generateWitness({
      findingId: "fnd_test_strcpy_001",
      ruleId: "REA-VULN-001-UNSAFE-MEMORY",
      category: "unsafe_memory_operations",
      source,
      sink: memSink,
      bufferCapacity: 64,
    });

    const lenConstraint = witness.constraints.find((c) => c.type === "min_length");
    expect(lenConstraint).toBeDefined();
    // 64 + 16 = 80 bytes
    expect(lenConstraint?.expectedValue).toBe(80);
    expect(witness.reproductionPayloadDescription).toContain("80");
  });
});

describe("Phase 7C: Sandboxed Precondition & Satisfiability Validation", () => {
  const generator = new WitnessGenerator();
  const validator = new WitnessValidator();

  const source: TaintSource = {
    kind: "network_socket",
    api: "recv",
    functionName: "handle_client",
    address: 0x1000,
    targetParameterOrReturn: 1,
  };

  const sink: TaintSink = {
    api: "system",
    functionName: "exec_action",
    address: 0x2050,
    vulnerableParameterIndex: 0,
  };

  it("proves exploitability when constraints are satisfiable within modeled environment", () => {
    const witness = generator.generateWitness({
      findingId: "fnd_test_cmd_002",
      ruleId: "REA-VULN-002-COMMAND-INJECTION",
      category: "command_injection",
      source,
      sink,
    });

    const validation = validator.validateWitness(witness, {
      maxInputLength: 1024,
      disallowedCharacters: ["\r", "\n"], // semicolons and pipes are allowed
    });

    expect(validation.isSatisfiable).toBe(true);
    expect(validation.isReproducible).toBe(true);
    expect(validation.exploitabilityStatus).toBe("PROVEN");
    expect(validation.conflictingGuards.length).toBe(0);
  });

  it("detects unsatisfiable constraints when active environment filters block triggers", () => {
    const witness = generator.generateWitness({
      findingId: "fnd_test_cmd_003",
      ruleId: "REA-VULN-002-COMMAND-INJECTION",
      category: "command_injection",
      source,
      sink,
    });

    // Active WAF or filter disallowing all command delimiters
    const validation = validator.validateWitness(witness, {
      disallowedCharacters: [";", "|", "&", "`", "$("],
    });

    expect(validation.isSatisfiable).toBe(false);
    expect(validation.isReproducible).toBe(false);
    expect(validation.exploitabilityStatus).toBe("UNSATISFIABLE");
    expect(validation.conflictingGuards.length).toBeGreaterThan(0);
    expect(validation.conflictingGuards[0]).toContain("disallowed by environment filter");
  });

  it("detects unsatisfiable overflow constraint when input length is bounded below buffer", () => {
    const memSink: TaintSink = {
      api: "strcpy",
      functionName: "parse_header",
      address: 0x3010,
      vulnerableParameterIndex: 1,
    };

    const witness = generator.generateWitness({
      findingId: "fnd_test_strcpy_003",
      ruleId: "REA-VULN-001-UNSAFE-MEMORY",
      category: "unsafe_memory_operations",
      source,
      sink: memSink,
      bufferCapacity: 128, // requires 144 bytes
    });

    // Environment only permits max 64 bytes
    const validation = validator.validateWitness(witness, {
      maxInputLength: 64,
    });

    expect(validation.isSatisfiable).toBe(false);
    expect(validation.exploitabilityStatus).toBe("UNSATISFIABLE");
    expect(validation.conflictingGuards[0]).toContain("Max environment input length (64 bytes) is strictly less than");
  });
});

describe("Phase 7 Negative Tests: Witness Contradictions & Theoretical Bounds", () => {
  const generator = new WitnessGenerator();
  const validator = new WitnessValidator();

  const source: TaintSource = {
    kind: "network_socket",
    api: "recv",
    functionName: "read_req",
    address: 0x1000,
    targetParameterOrReturn: 1,
  };

  const sink: TaintSink = {
    api: "system",
    functionName: "exec_action",
    address: 0x2050,
    vulnerableParameterIndex: 0,
  };

  it("classifies witness as THEORETICAL when bounds are omitted (not proven)", () => {
    const witness = generator.generateWitness({
      findingId: "fnd_test_cmd_theo",
      ruleId: "REA-VULN-002-COMMAND-INJECTION",
      category: "command_injection",
      source,
      sink,
    });

    const validation = validator.validateWitness(witness); // No bounds provided
    expect(validation.isSatisfiable).toBe(true);
    expect(validation.isReproducible).toBe(false);
    expect(validation.exploitabilityStatus).toBe("THEORETICAL");
  });

  it("rejects witness as UNSATISFIABLE when constraints are empty", () => {
    const emptyWitness = {
      ...generator.generateWitness({
        findingId: "fnd_empty",
        ruleId: "REA-TEST",
        category: "command_injection",
        source,
        sink,
      }),
      constraints: [],
    };

    const validation = validator.validateWitness(emptyWitness);
    expect(validation.isSatisfiable).toBe(false);
    expect(validation.exploitabilityStatus).toBe("UNSATISFIABLE");
    expect(validation.conflictingGuards[0]).toContain("no input constraints");
  });

  it("detects internal constraint contradictions (e.g. character required present and absent)", () => {
    const contradictoryWitness = {
      ...generator.generateWitness({
        findingId: "fnd_contra",
        ruleId: "REA-TEST",
        category: "command_injection",
        source,
        sink,
      }),
      constraints: [
        {
          parameter: "payload",
          type: "character_present" as const,
          expectedValue: [";"],
          description: "Must contain semicolon",
        },
        {
          parameter: "payload",
          type: "character_absent" as const,
          expectedValue: [";"],
          description: "Must NOT contain semicolon",
        },
      ],
    };

    const validation = validator.validateWitness(contradictoryWitness);
    expect(validation.isSatisfiable).toBe(false);
    expect(validation.exploitabilityStatus).toBe("UNSATISFIABLE");
    expect(validation.conflictingGuards[0]).toContain("Contradictory constraints");
  });
});


import { createHash } from "node:crypto";
import canonicalize from "canonicalize";
import type { TaintSink, TaintSource } from "../taint/types.js";
import type { ReachabilityPath } from "../cfg/types.js";
import type {
  ExecutionEnvironment,
  InputConstraint,
  WitnessArtifact,
} from "./types.js";

export interface WitnessGenerationInput {
  readonly findingId: string;
  readonly ruleId: string;
  readonly category: string;
  readonly source: TaintSource;
  readonly sink: TaintSink;
  readonly path?: ReachabilityPath | undefined;
  readonly bufferCapacity?: number | undefined;
  readonly environment?: Partial<ExecutionEnvironment> | undefined;
}

export class WitnessGenerator {
  /**
   * Synthesize a reproducible witness artifact from validated path and taint facts.
   */
  public generateWitness(input: WitnessGenerationInput): WitnessArtifact {
    const { findingId, ruleId, category, source, sink, path, bufferCapacity = 128 } = input;

    const constraints: InputConstraint[] = [];
    const preconditions: string[] = [];
    let payloadDescription = "";

    // 1. Generate category-specific mathematical & semantic constraints
    if (category === "command_injection") {
      constraints.push({
        parameter: "cmd_payload",
        type: "character_present",
        expectedValue: [";", "|", "&", "`", "$("],
        description: "Payload must contain command delimiter or command substitution syntax to break out of static command string.",
      });
      constraints.push({
        parameter: "cmd_payload",
        type: "character_absent",
        expectedValue: ["\0"],
        description: "Payload must not contain premature NUL bytes before command separator.",
      });
      preconditions.push(`Service receives raw network input via ${source.api} without shell sanitization`);
      preconditions.push(`Child shell process inherited execution privileges of ${sink.functionName}`);
      payloadDescription = "Payload format: '127.0.0.1; id' or '; reboot;'";
    } else if (category === "unsafe_memory_operations") {
      const minOverflow = bufferCapacity + 16;
      constraints.push({
        parameter: "input_length",
        type: "min_length",
        expectedValue: minOverflow,
        description: `Input byte sequence length must exceed destination buffer capacity (${bufferCapacity} bytes).`,
      });
      constraints.push({
        parameter: "input_content",
        type: "character_absent",
        expectedValue: ["\0"],
        description: "Payload must not contain NUL bytes prior to target offset to prevent premature copy termination.",
      });
      preconditions.push(`Destination stack or heap buffer allocated with fixed size <= ${bufferCapacity} bytes`);
      preconditions.push(`Function ${sink.functionName} copies buffer without length check`);
      payloadDescription = `Pattern: 'A' * ${minOverflow} to overflow adjacent return address or function pointer`;
    } else if (category === "path_traversal") {
      constraints.push({
        parameter: "filepath",
        type: "character_present",
        expectedValue: ["../", "..\\"],
        description: "Path input must contain relative parent directory traversal sequences.",
      });
      preconditions.push("Target service fails to canonicalize file path before filesystem access");
      payloadDescription = "Pattern: '../../../../etc/shadow'";
    } else {
      constraints.push({
        parameter: "generic_input",
        type: "magic_value",
        expectedValue: "EXPLOIT_TRIGGER",
        description: "Trigger condition for security candidate.",
      });
      payloadDescription = "Generic trigger payload";
    }

    const env: ExecutionEnvironment = {
      architecture: input.environment?.architecture ?? "ARM",
      endianness: input.environment?.endianness ?? "little",
      os: input.environment?.os ?? "linux",
      mode: "simulated_harness",
      configuration: input.environment?.configuration ?? {
        aslr: false,
        stackCanary: false,
      },
      runtimeVersion: "REA-Sandbox-v1.0",
    };

    const executionPathAddresses = path?.steps.map((s) => s.address) ?? [source.address, sink.address];
    const generatedAt = new Date().toISOString();

    // 2. Compute canonical digest
    const baseContent = {
      findingId,
      ruleId,
      category,
      source: { api: source.api, address: source.address, functionName: source.functionName },
      sink: { api: sink.api, address: sink.address, functionName: sink.functionName },
      executionPathAddresses,
      constraints,
      preconditions,
      environment: env,
    };

    const canonicalJson = canonicalize(baseContent) ?? JSON.stringify(baseContent);
    const artifactDigest = createHash("sha256").update(canonicalJson).digest("hex");
    const witnessId = `wit_${artifactDigest.slice(0, 32)}`;

    return {
      witnessId,
      findingId,
      ruleId,
      category,
      source: { api: source.api, address: source.address, functionName: source.functionName },
      sink: { api: sink.api, address: sink.address, functionName: sink.functionName },
      executionPathAddresses,
      constraints,
      preconditions,
      reproductionPayloadDescription: payloadDescription,
      environment: env,
      artifactDigest,
      generatedAt,
    };
  }
}


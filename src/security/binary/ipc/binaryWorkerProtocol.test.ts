/* eslint-disable max-lines-per-function */
/**
 * REA Phase 3A — Milestone 1: Focused Binary Worker IPC Protocol Test Suite
 *
 * Covers the 20 required protocol and framing test vectors:
 * 1. Valid request parsing.
 * 2. Valid response parsing.
 * 3. Unsupported protocol version.
 * 4. Unknown message type.
 * 5. Unknown fields (strict schema enforcement).
 * 6. Invalid SHA-256.
 * 7. Invalid task/run identifiers.
 * 8. Oversized control frame (> 64 KiB).
 * 9. Oversized analysis result (> 16 MiB).
 * 10. Malformed JSON.
 * 11. Truncated frame on EOF.
 * 12. Partial frame across multiple reads.
 * 13. Multiple messages in one read.
 * 14. Invalid UTF-8 bytes.
 * 15. Non-finite numbers (NaN, Infinity).
 * 16. Prototype-sensitive input (__proto__, constructor).
 * 17. Worker-supplied forged verdict rejection.
 * 18. Mismatched assessment or binary context.
 * 19. Duplicate message IDs.
 * 20. EOF with a complete final frame versus an incomplete frame.
 */

import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  BINARY_IPC_CONTROL_FRAME_MAX_BYTES,
  BINARY_WORKER_PROTOCOL_VERSION,
  binaryInputReferenceSchema,
  binaryWorkerAnalyzeRequestSchema,
  binaryWorkerAnalyzeResponseSchema,
  binaryWorkerIpcMessageSchema,
  validateBinaryInputReference,
  validateResponseContext,
  type BinaryWorkerAnalyzeRequest,
  type BinaryWorkerAnalyzeResponse,
} from "./binaryWorkerProtocol.js";
import {
  BinaryMessageFramer,
  safeJsonParse,
} from "./binaryMessageFramer.js";
import type { Result } from "../../../domain/result.js";

function unwrap<T>(res: Result<T, any>): T {
  if (!res.ok) {
    throw new Error(`Expected ok result, got error: ${JSON.stringify((res as any).error)}`);
  }
  return res.value;
}

function unwrapError<E>(res: Result<any, E>): E {
  if (res.ok) {
    throw new Error(`Expected error result, got value: ${JSON.stringify((res as any).value)}`);
  }
  return res.error;
}

const validBinarySha256 = "a".repeat(64);
const validTaskId = "tsk_11111111111111111111111111111111";
const validAssessmentId = "asm_22222222222222222222222222222222";
const validAssetId = "ast_33333333333333333333333333333333";
const validRunId = "run_44444444444444444444444444444444";
const validWorkerId = "wkr_55555555555555555555555555555555";

function createSampleAnalyzeRequest(): BinaryWorkerAnalyzeRequest {
  return {
    protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
    kind: "ANALYZE_REQUEST",
    messageId: randomUUID(),
    taskId: validTaskId,
    assessmentId: validAssessmentId,
    assetId: validAssetId,
    binarySha256: validBinarySha256,
    runId: validRunId,
    fencingToken: 1,
    workerId: validWorkerId,
    requestedStage: "ALL",
    binaryInput: {
      type: "file_path",
      path: "/sandbox/target_bin",
      expected_sha256: validBinarySha256,
      byte_size: 1024,
      read_only: true,
    },
    analysisConfiguration: {
      architecture: "ARM",
      entryPoints: ["main"],
      maxInstructions: 10000,
      maxCfgBlocks: 1000,
      maxPaths: 100,
    },
    deadline: Date.now() + 30000,
  };
}

function createSampleAnalyzeResponse(inReplyTo: string): BinaryWorkerAnalyzeResponse {
  return {
    protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
    kind: "ANALYZE_RESPONSE",
    messageId: randomUUID(),
    inReplyTo,
    taskId: validTaskId,
    assessmentId: validAssessmentId,
    assetId: validAssetId,
    binarySha256: validBinarySha256,
    runId: validRunId,
    fencingToken: 1,
    workerId: validWorkerId,
    stage: "ALL",
    executionStatus: "SUCCESS",
    decodeCompleteness: {
      isComplete: true,
      outcome: "SUCCESS",
      decodedBytes: 1024,
      totalBytes: 1024,
    },
    resultPayload: {
      metadata: {
        sha256: validBinarySha256,
        architecture: "ARM",
        endianness: "little",
        elfClass: "32",
        entryPoint: "0x1000",
        isExecutable: true,
        sectionsCount: 12,
        programHeadersCount: 4,
        dynamicLibraries: ["libc.so"],
      },
      candidates: [
        {
          ruleId: "REA-VULN-001",
          category: "command_injection",
          name: "system command injection",
          functionName: "handle_req",
          sinkApi: "system",
          functionAddress: "0x1000",
          callAddress: "0x1020",
          callerInfo: "main",
          detectionMethod: "L5_WITNESS",
          confidenceScore: 0.95,
          technicalDescription: "User input directly flows to system",
          cwe: ["CWE-78"],
        },
      ],
    },
    resultDigest: "b".repeat(64),
    diagnostics: ["Decoded 256 instructions"],
    resourceUsage: {
      cpuTimeMs: 45,
      peakMemoryBytes: 12 * 1024 * 1024,
      wallTimeMs: 60,
    },
  };
}

describe("REA Phase 3A — Milestone 1: IPC Protocol & Framing Suite", () => {
  // ==========================================================================
  // 1 & 2: Valid Request & Response Parsing
  // ==========================================================================

  it("TEST-1: Successfully parses and serializes valid BinaryWorkerRequest", () => {
    const req = createSampleAnalyzeRequest();
    const parseRes = binaryWorkerAnalyzeRequestSchema.safeParse(req);
    expect(parseRes.success).toBe(true);

    const framer = new BinaryMessageFramer();
    const serRes = framer.serialize(req);
    expect(serRes.ok).toBe(true);

    const serialized = unwrap(serRes);
    const framedRes = framer.push(serialized);
    expect(framedRes).toHaveLength(1);
    expect(framedRes[0]!.ok).toBe(true);
    expect(unwrap(framedRes[0]!)).toEqual(req);
  });

  it("TEST-2: Successfully parses and serializes valid BinaryWorkerResponse", () => {
    const res = createSampleAnalyzeResponse(randomUUID());
    const parseRes = binaryWorkerAnalyzeResponseSchema.safeParse(res);
    expect(parseRes.success).toBe(true);

    const framer = new BinaryMessageFramer();
    const serRes = framer.serialize(res);
    expect(serRes.ok).toBe(true);

    const framedRes = framer.push(unwrap(serRes));
    expect(framedRes).toHaveLength(1);
    expect(framedRes[0]!.ok).toBe(true);
    expect(unwrap(framedRes[0]!)).toEqual(res);
  });

  // ==========================================================================
  // 3 & 4: Protocol Version & Unknown Message Types
  // ==========================================================================

  it("TEST-3: Rejects unsupported protocol version", () => {
    const req: any = {
      ...createSampleAnalyzeRequest(),
      protocolVersion: "2.0.0",
    };
    const res = binaryWorkerAnalyzeRequestSchema.safeParse(req);
    expect(res.success).toBe(false);
  });

  it("TEST-4: Rejects unknown message type", () => {
    const req: any = {
      ...createSampleAnalyzeRequest(),
      kind: "UNKNOWN_KIND_INJECTION",
    };
    const res = binaryWorkerIpcMessageSchema.safeParse(req);
    expect(res.success).toBe(false);
  });

  // ==========================================================================
  // 5, 6, 7: Unknown Fields, Invalid SHA256 & Invalid Identifiers
  // ==========================================================================

  it("TEST-5: Rejects unknown fields due to strict schema validation", () => {
    const req: any = {
      ...createSampleAnalyzeRequest(),
      unauthorizedInjectedField: "malicious_payload",
    };
    const res = binaryWorkerAnalyzeRequestSchema.safeParse(req);
    expect(res.success).toBe(false);
    if (!res.success) {
      expect(res.error.issues[0]?.message).toContain("Unrecognized key");
    }
  });

  it("TEST-6: Rejects invalid or malformed SHA-256 digests", () => {
    const invalidHashes = [
      "A".repeat(64), // uppercase
      "a".repeat(63), // too short
      "a".repeat(65), // too long
      "g".repeat(64), // non-hex
      "1234",
    ];

    for (const badHash of invalidHashes) {
      const req: any = {
        ...createSampleAnalyzeRequest(),
        binarySha256: badHash,
      };
      const res = binaryWorkerAnalyzeRequestSchema.safeParse(req);
      expect(res.success).toBe(false);
    }
  });

  it("TEST-7: Rejects invalid task, run, assessment, and worker identifiers", () => {
    const req = createSampleAnalyzeRequest();

    // Wrong prefix on taskId
    expect(
      binaryWorkerAnalyzeRequestSchema.safeParse({ ...req, taskId: "bad_prefix_123" }).success,
    ).toBe(false);

    // Wrong prefix on runId
    expect(
      binaryWorkerAnalyzeRequestSchema.safeParse({ ...req, runId: "not_a_run" }).success,
    ).toBe(false);

    // Wrong prefix on assessmentId
    expect(
      binaryWorkerAnalyzeRequestSchema.safeParse({ ...req, assessmentId: "ast_should_be_asm" }).success,
    ).toBe(false);

    // Wrong prefix on workerId
    expect(
      binaryWorkerAnalyzeRequestSchema.safeParse({ ...req, workerId: "admin_root" }).success,
    ).toBe(false);
  });

  // ==========================================================================
  // 8 & 9: Oversized Control & Data Frames
  // ==========================================================================

  it("TEST-8: Rejects oversized control frames exceeding 64 KiB", () => {
    const framer = new BinaryMessageFramer();

    // Create a CANCEL control frame with an oversized reason
    const paddedReason = "x".repeat(BINARY_IPC_CONTROL_FRAME_MAX_BYTES + 10);
    const oversizedControlFrame = Buffer.from(
      JSON.stringify({
        protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
        kind: "CANCEL",
        messageId: randomUUID(),
        taskId: validTaskId,
        reason: paddedReason,
      }) + "\n",
      "utf8",
    );

    const res = framer.push(oversizedControlFrame);
    expect(res).toHaveLength(1);
    expect(res[0]!.ok).toBe(false);
    const errObj = unwrapError(res[0]!);
    expect(errObj.code).toBe("CONTROL_FRAME_OVERSIZED");
  });

  it("TEST-9: Rejects oversized analysis data frames exceeding data frame budget", () => {
    // Custom framer with a 512-byte data limit for testing
    const smallFramer = new BinaryMessageFramer({
      dataFrameMaxBytes: 512,
      maxPendingBytes: 1024,
    });

    const paddedMsg = Buffer.from(
      JSON.stringify({
        protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
        kind: "ANALYZE_REQUEST",
        messageId: randomUUID(),
        taskId: validTaskId,
        assessmentId: validAssessmentId,
        assetId: validAssetId,
        binarySha256: validBinarySha256,
        runId: validRunId,
        fencingToken: 1,
        workerId: validWorkerId,
        requestedStage: "ALL",
        binaryInput: {
          type: "file_path",
          path: "/sandbox/bin",
          expected_sha256: validBinarySha256,
          byte_size: 1024,
          read_only: true,
        },
        analysisConfiguration: {
          architecture: "ARM",
          entryPoints: ["main"],
          targetFunctions: Array.from({ length: 100 }, (_, i) => `function_padding_${i}`),
          maxInstructions: 10000,
          maxCfgBlocks: 1000,
          maxPaths: 100,
        },
        deadline: Date.now() + 30000,
      }) + "\n",
      "utf8",
    );

    const res = smallFramer.push(paddedMsg);
    expect(res).toHaveLength(1);
    expect(res[0]!.ok).toBe(false);
    expect(unwrapError(res[0]!).code).toBe("FRAME_OVERSIZED");
  });

  // ==========================================================================
  // 10 & 11: Malformed JSON & Truncated Frame on EOF
  // ==========================================================================

  it("TEST-10: Rejects malformed JSON syntax safely without crashing", () => {
    const framer = new BinaryMessageFramer();
    const badJson = Buffer.from('{"kind": "CANCEL", "truncated": true\n', "utf8");

    const res = framer.push(badJson);
    expect(res).toHaveLength(1);
    expect(res[0]!.ok).toBe(false);
    expect(unwrapError(res[0]!).code).toBe("MALFORMED_JSON");
  });

  it("TEST-11: Detects truncated frame when stream reaches EOF without terminal newline", () => {
    const framer = new BinaryMessageFramer();
    const partial = Buffer.from('{"kind": "CANCEL"', "utf8");

    const pushRes = framer.push(partial);
    expect(pushRes).toHaveLength(0); // Still buffering

    const endRes = framer.end();
    expect(endRes).toHaveLength(1);
    expect(endRes[0]!.ok).toBe(false);
    expect(unwrapError(endRes[0]!).code).toBe("FRAME_TRUNCATED");
  });

  // ==========================================================================
  // 12 & 13: Partial Frame Slicing & Multiple Frames in Single Read
  // ==========================================================================

  it("TEST-12: Handles partial frame across multiple reads correctly", () => {
    const framer = new BinaryMessageFramer();
    const req = createSampleAnalyzeRequest();
    const fullJson = JSON.stringify(req) + "\n";
    const fullBuf = Buffer.from(fullJson, "utf8");

    // Split across 3 separate reads
    const part1 = fullBuf.subarray(0, 50);
    const part2 = fullBuf.subarray(50, 150);
    const part3 = fullBuf.subarray(150);

    expect(framer.push(part1)).toHaveLength(0);
    expect(framer.push(part2)).toHaveLength(0);

    const finalRes = framer.push(part3);
    expect(finalRes).toHaveLength(1);
    expect(finalRes[0]!.ok).toBe(true);
    expect(unwrap(finalRes[0]!)).toEqual(req);
    expect(framer.end()).toHaveLength(0);
  });

  it("TEST-13: Handles multiple messages in a single read buffer", () => {
    const framer = new BinaryMessageFramer();
    const msg1 = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "CANCEL",
      messageId: randomUUID(),
      taskId: validTaskId,
      reason: "User cancelled 1",
    };
    const msg2 = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "CANCEL",
      messageId: randomUUID(),
      taskId: validTaskId,
      reason: "User cancelled 2",
    };

    const combined = Buffer.from(
      JSON.stringify(msg1) + "\n" + JSON.stringify(msg2) + "\n",
      "utf8",
    );

    const res = framer.push(combined);
    expect(res).toHaveLength(2);
    expect(res[0]!.ok).toBe(true);
    expect(res[1]!.ok).toBe(true);
    expect(unwrap(res[0]!)).toEqual(msg1);
    expect(unwrap(res[1]!)).toEqual(msg2);
  });

  // ==========================================================================
  // 14 & 15: Invalid UTF-8 & Non-Finite Numbers
  // ==========================================================================

  it("TEST-14: Rejects invalid UTF-8 byte sequences", () => {
    const framer = new BinaryMessageFramer();
    // 0xFF and 0xC0 0x80 are invalid UTF-8 sequences
    const invalidUtf8Buf = Buffer.from([0x7b, 0x22, 0xff, 0xfe, 0x22, 0x3a, 0x31, 0x7d, 0x0a]);

    const res = framer.push(invalidUtf8Buf);
    expect(res).toHaveLength(1);
    expect(res[0]!.ok).toBe(false);
    expect(unwrapError(res[0]!).code).toBe("INVALID_UTF8");
  });

  it("TEST-15: Rejects non-finite numbers (NaN, Infinity)", () => {
    const req = createSampleAnalyzeRequest();

    // NaN / Infinity cannot be represented in standard JSON, but if sent:
    const badReqs = [
      { ...req, fencingToken: NaN },
      { ...req, fencingToken: Infinity },
      { ...req, fencingToken: -Infinity },
      { ...req, deadline: Infinity },
    ];

    for (const bad of badReqs) {
      expect(binaryWorkerAnalyzeRequestSchema.safeParse(bad).success).toBe(false);
    }
  });

  // ==========================================================================
  // 16: Prototype Pollution Rejection
  // ==========================================================================

  it("TEST-16: Rejects prototype-sensitive input (__proto__, constructor)", () => {
    const framer = new BinaryMessageFramer();

    const poisonPayloads = [
      '{"kind": "CANCEL", "messageId": "bad", "__proto__": {"admin": true}}\n',
      '{"kind": "CANCEL", "constructor": {"prototype": {"polluted": true}}}\n',
      '{"kind": "CANCEL", "prototype": {"isAdmin": true}}\n',
    ];

    for (const poison of poisonPayloads) {
      const res = framer.push(Buffer.from(poison, "utf8"));
      expect(res).toHaveLength(1);
      expect(res[0]!.ok).toBe(false);
      expect(unwrapError(res[0]!).code).toBe("PROTOTYPE_POLLUTION");
    }
  });

  // ==========================================================================
  // 17: Worker-Supplied Forged Verdict Rejection
  // ==========================================================================

  it("TEST-17: Schema strictly rejects attempts by worker to award VERIFIED or FALSE_POSITIVE verdict", () => {
    const response = createSampleAnalyzeResponse(randomUUID());

    // Worker attempts to inject an authoritative verdict
    const forgedResponse1: any = {
      ...response,
      lifecycleState: "VERIFIED",
    };
    expect(binaryWorkerAnalyzeResponseSchema.safeParse(forgedResponse1).success).toBe(false);

    const forgedResponse2: any = {
      ...response,
      verificationStatus: "VERIFIED",
    };
    expect(binaryWorkerAnalyzeResponseSchema.safeParse(forgedResponse2).success).toBe(false);

    // Worker attempts to inject verdict inside candidates
    const forgedResponse3: any = {
      ...response,
      resultPayload: {
        ...response.resultPayload,
        candidates: [
          {
            ...response.resultPayload.candidates![0],
            lifecycleState: "VERIFIED",
            verificationStatus: "VERIFIED",
          },
        ],
      },
    };
    expect(binaryWorkerAnalyzeResponseSchema.safeParse(forgedResponse3).success).toBe(false);
  });

  // ==========================================================================
  // 18: Context Binding & Mismatch Verification
  // ==========================================================================

  it("TEST-18: Context validator detects and rejects mismatched assessment, asset, binary, or fencing token", () => {
    const response = createSampleAnalyzeResponse(randomUUID());
    const expectedContext = {
      assessmentId: validAssessmentId,
      assetId: validAssetId,
      binarySha256: validBinarySha256,
      runId: validRunId,
      taskId: validTaskId,
      fencingToken: 1,
      workerId: validWorkerId,
    };

    // Valid context passes
    expect(validateResponseContext(expectedContext, response).ok).toBe(true);

    // Mismatched assessmentId
    const resAsm = validateResponseContext(
      { ...expectedContext, assessmentId: "asm_foreign_0000000000000000000" },
      response,
    );
    expect(resAsm.ok).toBe(false);
    expect(unwrapError(resAsm).code).toBe("ASSESSMENT_MISMATCH");

    // Mismatched binarySha256
    const resBin = validateResponseContext(
      { ...expectedContext, binarySha256: "0".repeat(64) },
      response,
    );
    expect(resBin.ok).toBe(false);
    expect(unwrapError(resBin).code).toBe("BINARY_MISMATCH");

    // Stale fencing token
    const resFence = validateResponseContext(
      { ...expectedContext, fencingToken: 2 },
      response,
    );
    expect(resFence.ok).toBe(false);
    expect(unwrapError(resFence).code).toBe("FENCING_TOKEN_MISMATCH");
  });

  // ==========================================================================
  // 19: Duplicate Message ID Detection
  // ==========================================================================

  it("TEST-19: Detects and rejects duplicate message IDs across session", () => {
    const framer = new BinaryMessageFramer({ trackMessageIds: true });
    const duplicateId = randomUUID();

    const msg1 = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "CANCEL",
      messageId: duplicateId,
      taskId: validTaskId,
      reason: "Initial cancel",
    };
    const msg2 = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "CANCEL",
      messageId: duplicateId, // Same messageId
      taskId: validTaskId,
      reason: "Duplicate cancel attempt",
    };

    const res1 = framer.push(Buffer.from(JSON.stringify(msg1) + "\n", "utf8"));
    expect(res1[0]!.ok).toBe(true);

    const res2 = framer.push(Buffer.from(JSON.stringify(msg2) + "\n", "utf8"));
    expect(res2[0]!.ok).toBe(false);
    expect(unwrapError(res2[0]!).code).toBe("DUPLICATE_MESSAGE_ID");
  });

  // ==========================================================================
  // 20: Clean EOF vs Truncated EOF
  // ==========================================================================

  it("TEST-20: Verifies clean EOF with complete final frame vs incomplete truncated frame", () => {
    // Case A: Complete final frame ending with newline -> end() returns empty
    const framerA = new BinaryMessageFramer();
    const frameA = Buffer.from(
      JSON.stringify({
        protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
        kind: "CANCEL",
        messageId: randomUUID(),
        taskId: validTaskId,
        reason: "Clean termination",
      }) + "\n",
      "utf8",
    );
    expect(framerA.push(frameA)).toHaveLength(1);
    expect(framerA.end()).toHaveLength(0); // Clean EOF

    // Case B: Incomplete frame missing terminal newline -> end() reports FRAME_TRUNCATED
    const framerB = new BinaryMessageFramer();
    const frameB = Buffer.from(
      JSON.stringify({
        protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
        kind: "CANCEL",
        messageId: randomUUID(),
        taskId: validTaskId,
        reason: "Incomplete write",
      }), // Missing \n
      "utf8",
    );
    expect(framerB.push(frameB)).toHaveLength(0);
    const endRes = framerB.end();
    expect(endRes).toHaveLength(1);
    expect(endRes[0]!.ok).toBe(false);
    expect(unwrapError(endRes[0]!).code).toBe("FRAME_TRUNCATED");
  });

  // ==========================================================================
  // Additional: Binary Input Reference Path Traversal Protection
  // ==========================================================================

  it("TEST-21: BinaryInputReference rejects relative paths, path traversal, and root escape", () => {
    // Relative path rejected
    const relRes = validateBinaryInputReference({
      type: "file_path",
      path: "relative/path/bin",
      expected_sha256: validBinarySha256,
      byte_size: 100,
      read_only: true,
    });
    expect(relRes.ok).toBe(false);
    expect(unwrapError(relRes).code).toBe("INVALID_PATH");

    // Traversal .. rejected
    const travRes = validateBinaryInputReference({
      type: "file_path",
      path: "/sandbox/../../etc/shadow",
      expected_sha256: validBinarySha256,
      byte_size: 100,
      read_only: true,
    });
    expect(travRes.ok).toBe(false);
    expect(unwrapError(travRes).code).toBe("PATH_TRAVERSAL_DETECTED");

    // Escaping allowed root rejected
    const escapeRes = validateBinaryInputReference(
      {
        type: "file_path",
        path: "/other_root/target",
        expected_sha256: validBinarySha256,
        byte_size: 100,
        read_only: true,
      },
      "/sandbox/allowed",
    );
    expect(escapeRes.ok).toBe(false);
    expect(unwrapError(escapeRes).code).toBe("PATH_TRAVERSAL_DETECTED");
  });
});


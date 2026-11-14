import { describe, it, expect } from "vitest";
import {
  generateCompositeFingerprint,
  normalizeFilePath,
} from "./fingerprint.js";
import type { AssetId } from "../asset.js";
import type { FindingLocation } from "../finding.js";
import type { SecurityClassification } from "../classification.js";

describe("PackBoard Composite Fingerprint", () => {
  const baseAssetId = "ast_1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff" as AssetId;
  const baseLocation: FindingLocation = {
    file: "src/crypto/aes.c",
    function: "aes_encrypt_block",
    line: 42,
    column: 10,
    end_line: 42,
    module: "crypto",
    component: null,
    address: null,
    offset: null,
  };
  const baseClassification: SecurityClassification = {
    cve: [],
    cwe: ["CWE-119" as any],
    capec: [],
    mitre_attack: [],
    owasp: [],
  };

  it("normalizes Windows backslashes and case-insensitivity in file paths", () => {
    const p1 = normalizeFilePath("C:\\Project\\Src\\Crypto\\AES.c");
    const p2 = normalizeFilePath("project/src/crypto/aes.c");
    expect(p1).toBe("/project/src/crypto/aes.c");
    expect(p1.endsWith(p2)).toBe(true);
  });

  it("generates deterministic fingerprint for identical inputs", () => {
    const fp1 = generateCompositeFingerprint({
      asset_id: baseAssetId,
      location: baseLocation,
      classification: baseClassification,
      sink_identifier: "memcpy_buffer",
      data_flow_hash: "hash_xyz",
    });
    const fp2 = generateCompositeFingerprint({
      asset_id: baseAssetId,
      location: { ...baseLocation, line: 43 }, // Adjacent line
      classification: baseClassification,
      sink_identifier: "memcpy_buffer",
      data_flow_hash: "hash_xyz",
    });
    // Line differences alone do not alter the root cause fingerprint if function & sink are identical
    expect(fp1).toBe(fp2);
    expect(fp1).toMatch(/^[a-f0-9]{64}$/);
  });

  it("keeps separate findings distinct when sinks differ, even on adjacent lines", () => {
    const fp1 = generateCompositeFingerprint({
      asset_id: baseAssetId,
      location: baseLocation,
      classification: baseClassification,
      sink_identifier: "memcpy_buffer",
    });
    const fp2 = generateCompositeFingerprint({
      asset_id: baseAssetId,
      location: { ...baseLocation, line: 44 },
      classification: baseClassification,
      sink_identifier: "sprintf_buffer", // Different sink!
    });
    expect(fp1).not.toBe(fp2);
  });

  it("keeps separate findings distinct when CWE differs, even in same function", () => {
    const fp1 = generateCompositeFingerprint({
      asset_id: baseAssetId,
      location: baseLocation,
      classification: baseClassification, // CWE-119 (Buffer Overflow)
      sink_identifier: "buffer_out",
    });
    const fp2 = generateCompositeFingerprint({
      asset_id: baseAssetId,
      location: baseLocation,
      classification: {
        ...baseClassification,
        cwe: ["CWE-134" as any], // CWE-134 (Format String)
      },
      sink_identifier: "buffer_out",
    });
    expect(fp1).not.toBe(fp2);
  });
});


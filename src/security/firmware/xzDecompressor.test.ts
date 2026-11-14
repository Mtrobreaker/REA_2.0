import { describe, it, expect } from "vitest";
import { XzDecompressor } from "./XzDecompressor.js";
import { spawnSync } from "node:child_process";

describe("XzDecompressor", () => {
  it("resolves the project-local XZ binary", () => {
    const xzPath = XzDecompressor.resolveXzBinary();
    expect(xzPath).toContain("tools");
    expect(xzPath).toMatch(/xz(\.exe)?$/);
  });

  it("decompresses valid XZ stream with high fidelity", () => {
    const xzPath = XzDecompressor.resolveXzBinary();
    const originalText = "Hello REA Milestone 4.3 XZ Decompression Validation!\n".repeat(50);
    const originalBuf = Buffer.from(originalText, "utf-8");

    // Compress using xz executable
    const compRes = spawnSync(xzPath, ["-z", "-c"], { input: originalBuf, shell: false });
    expect(compRes.status).toBe(0);
    const compressed = compRes.stdout;
    expect(compressed.length).toBeGreaterThan(0);

    // Decompress via XzDecompressor
    const decompressed = XzDecompressor.decompressSync(compressed);
    expect(decompressed.toString("utf-8")).toBe(originalText);
  });

  it("handles empty input gracefully", () => {
    const res = XzDecompressor.decompressSync(Buffer.alloc(0));
    expect(res.length).toBe(0);
  });

  it("rejects corrupted input stream with typed failure", () => {
    const corrupted = Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0xde, 0xad, 0xbe, 0xef]);
    expect(() => {
      XzDecompressor.decompressSync(corrupted);
    }).toThrow(/XZ decompression failed with exit code/);
  });

  it("enforces maxOutputLength limit", () => {
    const xzPath = XzDecompressor.resolveXzBinary();
    const payload = Buffer.alloc(100_000, 0x41); // 100 KB
    const compRes = spawnSync(xzPath, ["-z", "-c"], { input: payload, shell: false });
    const compressed = compRes.stdout;

    expect(() => {
      XzDecompressor.decompressSync(compressed, { maxOutputLength: 50_000 });
    }).toThrow(/maximum allowed size limit/);
  });
});


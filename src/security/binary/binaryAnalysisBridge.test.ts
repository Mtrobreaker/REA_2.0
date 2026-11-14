import { describe, expect, it } from "vitest";
import { BinaryAnalysisBridge } from "./BinaryAnalysisBridge.js";
import { createTestElfImage } from "./testElfFixtures.js";

describe("BinaryAnalysisBridge ELF Metadata & Layout", () => {
  const bridge = new BinaryAnalysisBridge();

  it("extracts complete ELF metadata for a 32-bit ARM binary", async () => {
    const elfBuf = createTestElfImage({
      is64Bit: false,
      isLE: true,
      machine: 0x28, // ARM
      entryPoint: 0x8000,
      importedSymbols: ["strcpy", "system", "MD5_Init"],
      exportedSymbols: ["main", "handle_request"],
      strings: ["admin:admin", "telnetd -l /bin/sh", "debug=1"],
      dynamicLibraries: ["libc.so.0", "libcrypto.so.1.0.0"],
    });

    const res = await bridge.analyze({ buffer: elfBuf });
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const report = res.value;
    expect(report.metadata.elfClass).toBe("ELF32");
    expect(report.metadata.endianness).toBe("little");
    expect(report.metadata.architecture).toBe("ARM");
    expect(report.metadata.entryPoint).toBe("0x00008000");
    expect(report.metadata.isExecutable).toBe(true);
    expect(report.metadata.sha256).toHaveLength(64);

    // Verify sections
    expect(report.metadata.sections.length).toBeGreaterThanOrEqual(6);
    const secNames = report.metadata.sections.map((s) => s.name);
    expect(secNames).toContain(".text");
    expect(secNames).toContain(".rodata");
    expect(secNames).toContain(".dynsym");
    expect(secNames).toContain(".dynstr");

    // Verify dynamic libraries
    expect(report.metadata.dynamicLibraries).toContain("libc.so.0");
    expect(report.metadata.dynamicLibraries).toContain("libcrypto.so.1.0.0");
  });

  it("extracts complete ELF metadata for a 64-bit x86_64 binary", async () => {
    const elfBuf = createTestElfImage({
      is64Bit: true,
      isLE: true,
      machine: 0x3e, // x86_64
      entryPoint: 0x401000,
      importedSymbols: ["gets", "popen", "bind"],
      exportedSymbols: ["main", "serve_clients"],
      strings: ["password=test", "http://192.168.1.1"],
      dynamicLibraries: ["libc.so.6"],
    });

    const res = await bridge.analyze({ buffer: elfBuf });
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const report = res.value;
    expect(report.metadata.elfClass).toBe("ELF64");
    expect(report.metadata.architecture).toBe("x86_64");
    expect(report.metadata.entryPoint).toBe("0x0000000000401000");

    // Verify imported and exported symbols
    const importedNames = report.metadata.importedSymbols.map((s) => s.name);
    expect(importedNames).toContain("gets");
    expect(importedNames).toContain("popen");
    expect(importedNames).toContain("bind");

    const exportedNames = report.metadata.exportedSymbols.map((s) => s.name);
    expect(exportedNames).toContain("main");
    expect(exportedNames).toContain("serve_clients");
  });

  it("fails closed on malformed or non-ELF binary buffer", async () => {
    const invalidBuf = Buffer.from("MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00");
    const res1 = await bridge.analyze({ buffer: invalidBuf });
    expect(res1.ok).toBe(false);
    if (!res1.ok) {
      expect(res1.error.code).toBe("INVALID_BINARY");
    }

    const tinyBuf = Buffer.from([0x7f, 0x45, 0x4c, 0x46]);
    const res2 = await bridge.analyze({ buffer: tinyBuf });
    expect(res2.ok).toBe(false);
    if (!res2.ok) {
      expect(res2.error.code).toBe("INVALID_BINARY");
    }
  });
});

describe("BinaryAnalysisBridge Functions & Provenance", () => {
  const bridge = new BinaryAnalysisBridge();

  it("maps call relationships and security-sensitive APIs to caller functions", async () => {
    const elfBuf = createTestElfImage({
      is64Bit: false,
      isLE: true,
      machine: 0x28,
      entryPoint: 0x10000,
      importedSymbols: ["strcpy", "system", "MD5_Init"],
      exportedSymbols: ["main", "network_handler"],
      strings: ["root:admin", "/bin/sh"],
    });

    const res = await bridge.analyze({ buffer: elfBuf });
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const report = res.value;
    expect(report.functions.length).toBeGreaterThanOrEqual(2);

    const mainFunc = report.functions.find((f) => f.name === "main");
    expect(mainFunc).toBeDefined();
    expect(mainFunc?.securitySensitiveCalls).toContain("strcpy");
    expect(mainFunc?.securitySensitiveCalls).toContain("system");
    expect(mainFunc?.stringReferences).toContain("/bin/sh");

    // Verify call relationships
    expect(report.callRelationships.length).toBeGreaterThan(0);
    expect(report.callRelationships.some((c) => c.caller === "main" && c.callee === "strcpy")).toBe(true);

    // Verify analysis provenance
    expect(report.provenance.provider).toBe("rea_inprocess_elf_engine");
    expect(report.provenance.executionMode).toBe("in-process");
    expect(report.provenance.version).toBe("rea-6.7.0");
  });
});


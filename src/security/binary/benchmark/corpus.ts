import { createTestElfImage } from "../testElfFixtures.js";
import type { BenchmarkSample } from "./types.js";

/**
 * Standardized Benchmark Corpus for Embedded Binary Vulnerability Verification.
 * Covers ARM, MIPS, and x86_64 architectures across true vulnerabilities,
 * mitigated variants, false positives (constants/dead code), and inconclusive cases.
 * Each sample supplies concrete machine code in .text decoded and analyzed by REA.
 */
export function getStandardBenchmarkCorpus(): readonly BenchmarkSample[] {
  return [
    // 1. ARM: True Command Injection via network source
    {
      id: "ARM-VULN-001-CMD-INJECTION",
      name: "Network-driven Command Injection",
      architecture: "ARM",
      category: "command_injection",
      groundTruth: "VULNERABLE",
      description: "Network service consumes request payload via recv() and executes system() without sanitization.",
      binaryBuffer: createTestElfImage({
        machine: 0x28,
        is64Bit: false,
        isLE: true,
        importedSymbols: ["recv", "system"],
        exportedSymbols: ["main"],
        strings: ["/bin/sh -c", "cmd_exec"],
        textBytes: new Uint8Array([
          0x0e, 0x00, 0x00, 0xeb, // bl 0x10040 (recv)
          0x15, 0x00, 0x00, 0xeb, // bl 0x10060 (system)
          0x1e, 0xff, 0x2f, 0xe1, // bx lr
        ]),
      }),
      expectedCandidate: true,
      expectedVerified: true,
    },

    // 2. ARM: Mitigated Command Injection (Dominating Whitelist Guard)
    {
      id: "ARM-FIXED-001-CMD-SANITIZED",
      name: "Sanitized Command Execution with Whitelist",
      architecture: "ARM",
      category: "command_injection",
      groundTruth: "FIXED_MITIGATED",
      description: "Service invokes system() but strictly verifies input against character whitelist.",
      binaryBuffer: createTestElfImage({
        machine: 0x28,
        is64Bit: false,
        isLE: true,
        importedSymbols: ["recv", "strspn", "system"],
        exportedSymbols: ["main"],
        strings: ["whitelist=0123456789", "system_safe"],
        textBytes: new Uint8Array([
          0x0e, 0x00, 0x00, 0xeb, // bl 0x10040 (recv)
          0x15, 0x00, 0x00, 0xeb, // bl 0x10060 (strspn sanitizer)
          0x1c, 0x00, 0x00, 0xeb, // bl 0x10080 (system)
          0x1e, 0xff, 0x2f, 0xe1, // bx lr
        ]),
      }),
      expectedCandidate: true,
      expectedVerified: false,
    },

    // 3. ARM: False Positive (Sink consumes static compile-time constant string)
    {
      id: "ARM-FP-001-CONSTANT-ARG",
      name: "Hardcoded System Invocation",
      architecture: "ARM",
      category: "command_injection",
      groundTruth: "FALSE_POSITIVE",
      description: "Service invokes system() with a static hardcoded constant string literal.",
      binaryBuffer: createTestElfImage({
        machine: 0x28,
        is64Bit: false,
        isLE: true,
        importedSymbols: ["system"],
        exportedSymbols: ["main"],
        strings: ["/sbin/ifconfig eth0 up", "/bin/date"],
        textBytes: new Uint8Array([
          0x0e, 0x00, 0x00, 0xeb, // bl 0x10040 (system)
          0x1e, 0xff, 0x2f, 0xe1, // bx lr
        ]),
      }),
      expectedCandidate: true,
      expectedVerified: false,
    },

    // 4. ARM: False Positive (Sink located in unreachable dead code)
    {
      id: "ARM-FP-002-DEAD-CODE",
      name: "Dead Code Memory Copy",
      architecture: "ARM",
      category: "unsafe_memory_operations",
      groundTruth: "FALSE_POSITIVE",
      description: "Dangerous strcpy() is present in a completely uncalled dead function.",
      binaryBuffer: createTestElfImage({
        machine: 0x28,
        is64Bit: false,
        isLE: true,
        importedSymbols: ["strcpy"],
        exportedSymbols: ["main", "dead_func"],
        strings: ["dead_func"],
        textBytes: new Uint8Array([
          // main at 0x10000: returns immediately
          0x1e, 0xff, 0x2f, 0xe1, // bx lr
          // 60 bytes padding to 0x10040
          ...new Uint8Array(60),
          // dead_func at 0x10040: calls strcpy at 0x10080
          0x0e, 0x00, 0x00, 0xeb, // bl 0x10080 (strcpy)
          0x1e, 0xff, 0x2f, 0xe1, // bx lr
        ]),
      }),
      expectedCandidate: true,
      expectedVerified: false,
    },

    // 5. MIPS: True Buffer Overflow (Unsafe gets)
    {
      id: "MIPS-VULN-001-MEM-OVERFLOW",
      name: "MIPS Unbounded gets() Stack Overflow",
      architecture: "MIPS",
      category: "unsafe_memory_operations",
      groundTruth: "VULNERABLE",
      description: "MIPS daemon invokes gets() to read input into fixed stack buffer.",
      binaryBuffer: createTestElfImage({
        machine: 0x08,
        is64Bit: false,
        isLE: true,
        importedSymbols: ["gets"],
        exportedSymbols: ["main"],
        strings: ["Enter password:"],
        textBytes: new Uint8Array([
          0x10, 0x40, 0x00, 0x0c, // jal 0x10040 (gets)
          0x00, 0x00, 0x00, 0x00, // nop (delay slot)
          0x08, 0x00, 0xe0, 0x03, // jr $ra
          0x00, 0x00, 0x00, 0x00, // nop (delay slot)
        ]),
      }),
      expectedCandidate: true,
      expectedVerified: true,
    },

    // 6. MIPS: Fixed Memory Copy (Guarded fgets)
    {
      id: "MIPS-FIXED-001-BOUNDED-COPY",
      name: "MIPS Bounded Input Reader",
      architecture: "MIPS",
      category: "unsafe_memory_operations",
      groundTruth: "FIXED_MITIGATED",
      description: "MIPS daemon uses bounded fgets() with explicit size limit.",
      binaryBuffer: createTestElfImage({
        machine: 0x08,
        is64Bit: false,
        isLE: true,
        importedSymbols: ["fgets"],
        exportedSymbols: ["main"],
        strings: ["Enter username:"],
        textBytes: new Uint8Array([
          0x10, 0x40, 0x00, 0x0c, // jal 0x10040 (fgets)
          0x00, 0x00, 0x00, 0x00, // nop (delay slot)
          0x08, 0x00, 0xe0, 0x03, // jr $ra
          0x00, 0x00, 0x00, 0x00, // nop (delay slot)
        ]),
      }),
      expectedCandidate: false,
      expectedVerified: false,
    },

    // 7. x86_64: Inconclusive Call (Traverses indirect call via pointer)
    {
      id: "X86-INCONCL-001-INDIRECT-CALL",
      name: "x86_64 Indirect Function Pointer Dispatch",
      architecture: "x86_64",
      category: "command_injection",
      groundTruth: "INCONCLUSIVE",
      description: "Path to system() passes through an unresolved runtime function pointer.",
      binaryBuffer: createTestElfImage({
        machine: 0x3e,
        is64Bit: true,
        isLE: true,
        importedSymbols: ["recv", "system"],
        exportedSymbols: ["main"],
        strings: ["call_target"],
        textBytes: new Uint8Array([
          0xff, 0x15, 0x5a, 0x00, 0x00, 0x00, // call *0x5a(%rip) -> target 0x10060 (system)
          0xc3, // ret
        ]),
      }),
      expectedCandidate: true,
      expectedVerified: false,
    },

    // 8. x86_64: True Path Traversal
    {
      id: "X86-VULN-001-PATH-TRAVERSAL",
      name: "x86_64 File Path Traversal",
      architecture: "x86_64",
      category: "path_traversal",
      groundTruth: "VULNERABLE",
      description: "File handler uses fopen() with client query parameter without traversal check.",
      binaryBuffer: createTestElfImage({
        machine: 0x3e,
        is64Bit: true,
        isLE: true,
        importedSymbols: ["fopen"],
        exportedSymbols: ["main"],
        strings: ["/www/public/", "../../../etc/shadow", "path=%s"],
        textBytes: new Uint8Array([
          0xe8, 0x3b, 0x00, 0x00, 0x00, // call 0x10040 (fopen)
          0xc3, // ret
        ]),
      }),
      expectedCandidate: true,
      expectedVerified: true,
    },
  ];
}

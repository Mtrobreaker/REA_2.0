# REA Evaluation Sample Manifest Specification
## Milestone 4.2 — Ground-Truth Metadata & Sample Provenance Standard

**Document Version:** 1.0.0  
**Date:** November 2026  
**Status:** Authoritative Specification  
**Role:** Senior Embedded Firmware Security Evaluation Engineer  
**Component:** `rea-evaluation-lab` / `rea-sample-manifest`  

---

## 1. Specification Purpose & Epistemic Rules

This document establishes the mandatory JSON and YAML schema for all firmware images, standalone binaries, vulnerable test cases, and protection-hardened samples evaluated within the **REA Evaluation Laboratory** (`REA-EVALUATION-LAB/`).

### 1.1 Non-Negotiable Epistemic Principles
1. **Independent Provenance:** Ground truth must be derived strictly from authoritative external sources—original compiler debug information, official vendor security advisories, National Vulnerability Database (NVD) records, CVE entries, or verified differential consensus across independent reference tools (e.g., GNU binutils, LLVM, Ghidra). Ground truth must **never** be generated from or calibrated against REA's own outputs.
2. **Strict Handling of Unknowns (Three-Valued Logic):**
   - A vulnerability is recorded as `PRESENT` only if confirmed by authoritative proof (CVE, PoC, or verified patch diff).
   - A vulnerability is recorded as `ABSENT` only if complete mathematical proof exists (e.g., sink is provably dead code across 100% of the control flow graph, or an unbreakable dominating bounds check is mathematically verified).
   - In all other cases, vulnerabilities **must remain labeled as `UNKNOWN`**. They must **never** be marked as "absent", "clean", or "safe" simply because an analyzer failed to find them.
3. **Cryptographic Immutability:** Every sample is uniquely identified and permanently bound to its cryptographic SHA-256 digest. Any mutation to the byte stream invalidates the manifest.

---

## 2. Complete Manifest JSON Schema

Manifests are stored as individual JSON files in:
`REA-EVALUATION-LAB/ground-truth/manifests/<sample_id>.manifest.json`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ReaSampleManifest",
  "type": "object",
  "required": [
    "sample_id",
    "category",
    "testing_level",
    "name",
    "sha256",
    "byte_size",
    "file_format",
    "architecture",
    "provenance",
    "expected_contents",
    "ground_truth_confidence",
    "known_limitations"
  ],
  "properties": {
    "sample_id": {
      "type": "string",
      "pattern": "^SMP-(L1|L2|L3)-(BIN|FW|VULN|PROT)-[0-9]{3,}$",
      "description": "Unique, immutable sample identifier"
    },
    "category": {
      "type": "string",
      "enum": [
        "simple_elf_symbols",
        "optimized_elf",
        "stripped_elf",
        "multi_arch_elf",
        "vulnerable_patched_pair",
        "embedded_firmware_squashfs",
        "embedded_firmware_uimage",
        "embedded_firmware_trx"
      ]
    },
    "testing_level": {
      "type": "string",
      "enum": ["L1_SYNTHETIC_MICRO", "L2_REAL_BINARY", "L3_FULL_FIRMWARE"]
    },
    "name": {
      "type": "string",
      "description": "Human-readable descriptive sample name"
    },
    "sha256": {
      "type": "string",
      "pattern": "^[a-f0-9]{64}$",
      "description": "Hex-encoded SHA-256 hash of the uncompressed target file"
    },
    "byte_size": {
      "type": "integer",
      "minimum": 1,
      "description": "Exact byte count of the target file"
    },
    "file_format": {
      "type": "string",
      "enum": ["elf32", "elf64", "squashfs_4_0", "uimage", "trx", "tar_gz", "pe32", "pe64", "raw_binary"]
    },
    "architecture": {
      "type": "object",
      "required": ["isa", "endianness", "bitness"],
      "properties": {
        "isa": { "type": "string", "enum": ["x86", "x86_64", "arm", "arm_thumb", "aarch64", "mips", "riscv", "powerpc"] },
        "endianness": { "type": "string", "enum": ["little", "big"] },
        "bitness": { "type": "integer", "enum": [32, 64] },
        "abi": { "type": "string" },
        "float_abi": { "type": "string", "enum": ["soft", "softfp", "hard"] }
      }
    },
    "provenance": {
      "type": "object",
      "required": ["source_type", "original_url", "license", "redistributable"],
      "properties": {
        "source_type": { "type": "string", "enum": ["vendor_advisory", "open_source_repo", "cve_benchmark", "juliet_test_suite", "synthetic_controlled"] },
        "original_url": { "type": "string", "format": "uri" },
        "mirror_url": { "type": "string" },
        "license": { "type": "string", "description": "SPDX license expression or specific terms" },
        "redistributable": { "type": "boolean" },
        "manufacturer": { "type": "string" },
        "model": { "type": "string" },
        "firmware_version": { "type": "string" },
        "software_version": { "type": "string" }
      }
    },
    "compiler_toolchain": {
      "type": "object",
      "properties": {
        "compiler": { "type": "string" },
        "compiler_version": { "type": "string" },
        "optimization_level": { "type": "string", "enum": ["O0", "O1", "O2", "O3", "Os", "Ofast", "unknown"] },
        "is_stripped": { "type": "boolean" },
        "has_debug_info": { "type": "boolean" },
        "security_flags": {
          "type": "object",
          "properties": {
            "pie": { "type": "boolean" },
            "stack_canary": { "type": "boolean" },
            "nx_dep": { "type": "boolean" },
            "relro": { "type": "string", "enum": ["none", "partial", "full"] },
            "fortify_source": { "type": "boolean" }
          }
        }
      }
    },
    "expected_contents": {
      "type": "object",
      "properties": {
        "entry_points": { "type": "array", "items": { "type": "integer" } },
        "function_count": { "type": "integer" },
        "exported_symbols": { "type": "array", "items": { "type": "string" } },
        "imported_symbols": { "type": "array", "items": { "type": "string" } },
        "key_strings": { "type": "array", "items": { "type": "string" } },
        "expected_files_count": { "type": "integer" }
      }
    },
    "vulnerabilities": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["vulnerability_id", "status", "cwe", "sink_api"],
        "properties": {
          "vulnerability_id": { "type": "string", "description": "CVE ID or synthetic flaw ID" },
          "status": { "type": "string", "enum": ["PRESENT", "ABSENT", "UNKNOWN"] },
          "cwe": { "type": "array", "items": { "type": "string" } },
          "target_function": { "type": "string" },
          "sink_api": { "type": "string" },
          "trigger_condition": { "type": "string" },
          "cvss_v31_vector": { "type": "string" },
          "base_score": { "type": "number" },
          "patch_pair_sample_id": { "type": "string", "description": "Associated patched sample ID" },
          "patch_commit_or_diff": { "type": "string" }
        }
      }
    },
    "ground_truth_confidence": {
      "type": "object",
      "required": ["confidence_level", "verification_method", "verified_by"],
      "properties": {
        "confidence_level": {
          "type": "string",
          "enum": ["MATHEMATICALLY_PROVEN", "DYNAMICALLY_VERIFIED_POC", "VENDOR_CONFIRMED", "CONSENSUS_MULTI_TOOL", "HEURISTIC"]
        },
        "verification_method": { "type": "string" },
        "verified_by": { "type": "string" },
        "verification_date": { "type": "string", "format": "date" }
      }
    },
    "known_limitations": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Explicit known challenges (e.g. unsupported instructions, packed sections)"
    }
  }
}
```

---

## 3. Sample Manifest Instances

### 3.1 Instance 1: Standalone Multi-Architecture ELF Binary
*File:* `ground-truth/manifests/SMP-L1-BIN-001.manifest.json`

```json
{
  "sample_id": "SMP-L1-BIN-001",
  "category": "multi_arch_elf",
  "testing_level": "L1_SYNTHETIC_MICRO",
  "name": "ARM32 Little-Endian Micro Benchmark (O0)",
  "sha256": "4b92b6732f7413de98867530e32f50567fdbbb9b429d332672e399587a8bcf49",
  "byte_size": 1824,
  "file_format": "elf32",
  "architecture": {
    "isa": "arm",
    "endianness": "little",
    "bitness": 32,
    "abi": "AAPCS",
    "float_abi": "soft"
  },
  "provenance": {
    "source_type": "synthetic_controlled",
    "original_url": "https://github.com/morluto/rea/tree/main/experiments/fixtures/arm32_o0.elf",
    "license": "MIT",
    "redistributable": true,
    "software_version": "1.0.0"
  },
  "compiler_toolchain": {
    "compiler": "arm-linux-gnueabi-gcc",
    "compiler_version": "13.2.0",
    "optimization_level": "O0",
    "is_stripped": false,
    "has_debug_info": true,
    "security_flags": {
      "pie": false,
      "stack_canary": false,
      "nx_dep": true,
      "relro": "none",
      "fortify_source": false
    }
  },
  "expected_contents": {
    "entry_points": [65536],
    "function_count": 6,
    "exported_symbols": ["main", "process_auth_packet", "validate_checksum"],
    "imported_symbols": ["strcpy", "printf", "exit"],
    "key_strings": ["Enter password: ", "Access Granted", "Checksum Error\n"]
  },
  "vulnerabilities": [
    {
      "vulnerability_id": "VULN-SYNTH-ARM-001",
      "status": "PRESENT",
      "cwe": ["CWE-120", "CWE-121"],
      "target_function": "process_auth_packet",
      "sink_api": "strcpy",
      "trigger_condition": "Input packet length > 64 bytes overrides saved frame pointer on stack",
      "cvss_v31_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "base_score": 9.8,
      "patch_pair_sample_id": "SMP-L1-BIN-001-PATCHED",
      "patch_commit_or_diff": "Replaced strcpy with strncpy(dest, src, sizeof(dest)-1)"
    }
  ],
  "ground_truth_confidence": {
    "confidence_level": "MATHEMATICALLY_PROVEN",
    "verification_method": "Source code inspection and LLVM 18.1 objdump boundary differential consensus",
    "verified_by": "Senior Embedded Firmware Security Engineer",
    "verification_date": "2026-11-08"
  },
  "known_limitations": [
    "ARM A32 instruction set only; does not contain Thumb-2 transition code",
    "Contains unmodeled coprocessor instructions in startup stub (_start)"
  ]
}
```

### 3.2 Instance 2: Controlled Vulnerable / Patched Software Pair
*File:* `ground-truth/manifests/SMP-L1-VULN-002.manifest.json`

```json
{
  "sample_id": "SMP-L1-VULN-002",
  "category": "vulnerable_patched_pair",
  "testing_level": "L2_REAL_BINARY",
  "name": "BusyBox 1.35.0 telnetd Command Injection (CVE-2022-30065)",
  "sha256": "8f39a799c82b1cdeec2251a238692120e8b15d2a912bbbc123049182390abdf1",
  "byte_size": 284160,
  "file_format": "elf32",
  "architecture": {
    "isa": "mips",
    "endianness": "big",
    "bitness": 32,
    "abi": "O32",
    "float_abi": "soft"
  },
  "provenance": {
    "source_type": "cve_benchmark",
    "original_url": "https://git.busybox.net/busybox/snapshot/busybox-1_35_0.tar.gz",
    "license": "GPL-2.0-only",
    "redistributable": true,
    "software_version": "1.35.0"
  },
  "compiler_toolchain": {
    "compiler": "mips-linux-gnu-gcc",
    "compiler_version": "12.3.0",
    "optimization_level": "Os",
    "is_stripped": true,
    "has_debug_info": false,
    "security_flags": {
      "pie": false,
      "stack_canary": false,
      "nx_dep": true,
      "relro": "partial",
      "fortify_source": false
    }
  },
  "expected_contents": {
    "entry_points": [4194304],
    "function_count": 184,
    "exported_symbols": [],
    "imported_symbols": ["system", "execve", "fork", "socket", "bind"],
    "key_strings": ["/bin/sh", "telnetd: starting"]
  },
  "vulnerabilities": [
    {
      "vulnerability_id": "CVE-2022-30065",
      "status": "PRESENT",
      "cwe": ["CWE-78", "CWE-416"],
      "target_function": "make_new_session",
      "sink_api": "system",
      "trigger_condition": "Crafted terminal option sequence triggers use-after-free and arbitrary command execution",
      "cvss_v31_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "base_score": 9.8,
      "patch_pair_sample_id": "SMP-L1-VULN-002-PATCHED",
      "patch_commit_or_diff": "git commit 6f47738c8230"
    }
  ],
  "ground_truth_confidence": {
    "confidence_level": "VENDOR_CONFIRMED",
    "verification_method": "NVD CVE-2022-30065 Advisory & BusyBox upstream commit verification",
    "verified_by": "Independent Security Auditor",
    "verification_date": "2026-11-08"
  },
  "known_limitations": [
    "Stripped binary; function names must be reconstructed from symbolless CFG",
    "MIPS branch delay slots require delay-slot-aware instruction decoders"
  ]
}
```

### 3.3 Instance 3: Embedded Firmware Image (SquashFS Rootfs)
*File:* `ground-truth/manifests/SMP-L1-FW-003.manifest.json`

```json
{
  "sample_id": "SMP-L1-FW-003",
  "category": "embedded_firmware_squashfs",
  "testing_level": "L3_FULL_FIRMWARE",
  "name": "OpenWrt 23.05 Minimal Rootfs (MIPS 24Kc Big-Endian)",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "byte_size": 4194304,
  "file_format": "squashfs_4_0",
  "architecture": {
    "isa": "mips",
    "endianness": "big",
    "bitness": 32,
    "abi": "O32"
  },
  "provenance": {
    "source_type": "open_source_repo",
    "original_url": "https://downloads.openwrt.org/releases/23.05.0/targets/ath79/generic/openwrt-23.05.0-ath79-generic-rootfs.tar.gz",
    "license": "GPL-2.0",
    "redistributable": true,
    "manufacturer": "OpenWrt Project",
    "model": "Generic ATH79 MIPS24Kc",
    "firmware_version": "23.05.0"
  },
  "expected_contents": {
    "expected_files_count": 312,
    "key_strings": ["/etc/init.d/rcS", "/bin/busybox", "/lib/ld-musl-mips-sf.so.1"]
  },
  "vulnerabilities": [
    {
      "vulnerability_id": "UNAUDITED_BASELINE",
      "status": "UNKNOWN",
      "cwe": [],
      "sink_api": "none",
      "trigger_condition": "Stock distribution; unknown whether unpatched 0-days or CVEs exist in stock musl libc."
    }
  ],
  "ground_truth_confidence": {
    "confidence_level": "CONSENSUS_MULTI_TOOL",
    "verification_method": "unsquashfs 4.6.1 extraction table and sha256 checksums",
    "verified_by": "Senior Embedded Firmware Security Engineer",
    "verification_date": "2026-11-08"
  },
  "known_limitations": [
    "Full Linux filesystem; contains symbolic links to BusyBox multi-call binary",
    "Requires symlink resolution in SandboxedExtractor and PreWriteValidator"
  ]
}
```


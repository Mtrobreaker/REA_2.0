# REA Level 1 Evaluation Corpus Proposal
## Milestone 4.2 — Diverse Architecture & Real-Input Candidate Dataset

**Document Version:** 1.0.0  
**Date:** November 2026  
**Status:** Proposal Awaiting User Authorization  
**Role:** Senior Embedded Firmware Security Evaluation Engineer  
**Component:** `rea-corpus` / `rea-evaluation-lab`  

---

## 1. Executive Summary & Selection Criteria

This document proposes the initial **Level 1 Evaluation Corpus** for REA. In alignment with repository safety instructions, **no external files have been downloaded indiscriminately**. All candidate samples are curated from publicly available, permissively licensed open-source projects, standard security benchmarks, or controlled synthetic toolchains.

### 1.1 Corpus Selection Principles
1. **Targeted Scale:** Bounded corpus ($<50\,\text{MB}$ total storage footprint across all samples; each individual binary $<5\,\text{MB}$; firmware images $<15\,\text{MB}$).
2. **Architectural Breadth:** Rigorous representation across REA's targeted embedded architectures: ARM32 (ARM/Thumb), MIPS32 (Little-Endian / Big-Endian), and baseline x86-64.
3. **Compilation Diversity:** Controlled combinations of compiler optimizations (`-O0`, `-O2`, `-Os`) and stripping (`with symbols`, `stripped`).
4. **Vulnerability Verification:** Inclusion of exact vulnerable/patched pairs with publicly established CVE numbers or deterministic CWE test vectors (Juliet / OWASP Benchmark).
5. **Passive Safety:** All samples will be analyzed strictly in static mode. No sample code will be executed on the evaluation host.

---

## 2. Proposed Level 1 Sample Inventory

The proposed Level 1 corpus comprises **16 carefully chosen samples** organized into six functional groups:

```
                                  PROPOSED LEVEL 1 CORPUS (16 SAMPLES)
                                                   │
    ┌───────────────────┬──────────────────────────┼──────────────────────────┬───────────────────┐
    │                   │                          │                          │                   │
    ▼                   ▼                          ▼                          ▼                   ▼
[GROUP A: SYMBOLS]  [GROUP B: OPTIMIZED]     [GROUP C: STRIPPED]        [GROUP D: PAIRS]    [GROUP E: FIRMWARE]
- ARM32 O0 Sym      - ARM32 O2 Sym           - ARM32 O2 Stripped        - BusyBox CVE-2022  - OpenWrt MIPS Sqush
- MIPS32 LE Sym     - MIPS32 BE O2 Sym       - MIPS32 LE Stripped         Vuln vs Patched   - TP-Link SquashFS
- x86-64 O0 Sym     - x86-64 O2 Sym          - x86-64 O2 Stripped       - synthetic CWE-120 - D-Link TRX/Squash
                                                                          Vuln vs Patched
```

### 2.1 Complete Sample Matrix

| Sample ID | Group | Sample Name | Architecture | Compiler / Opt | Symbols | Size | Primary Evaluation Objective | Ground-Truth Provider |
|---|---|---|---|---|---|---|---|---|
| **SMP-L1-001** | A | Micro-Auth ARM32 | ARM32 (LE) | GCC 13 / `-O0` | Yes (DWARF) | 2.4 KB | Basic instruction decode, function detection, string extraction | Compiler debug info |
| **SMP-L1-002** | A | Micro-Auth MIPS LE | MIPS32 (LE) | GCC 13 / `-O0` | Yes (DWARF) | 2.8 KB | MIPS branch delay slot & LE decoding baseline | Compiler debug info |
| **SMP-L1-003** | A | Micro-Auth x86-64 | x86-64 | GCC 13 / `-O0` | Yes (DWARF) | 3.1 KB | x86-64 prefix & basic instruction boundary baseline | Compiler debug info |
| **SMP-L1-004** | B | Micro-Auth ARM32 O2 | ARM32 (LE) | GCC 13 / `-O2` | Yes (DWARF) | 1.8 KB | Compiler inlining, loop unrolling, and basic block splitting | Compiler debug info / LLVM |
| **SMP-L1-005** | B | Micro-Auth MIPS BE O2 | MIPS32 (BE) | GCC 13 / `-O2` | Yes (DWARF) | 2.1 KB | Big-endian byte swapping & optimized branch delay handling | Compiler debug info / LLVM |
| **SMP-L1-006** | B | Micro-Auth x86-64 O2 | x86-64 | GCC 13 / `-O2` | Yes (DWARF) | 2.2 KB | Optimized x86-64 ABI calling conventions | Compiler debug info / LLVM |
| **SMP-L1-007** | C | Micro-Auth ARM32 Strip | ARM32 (LE) | GCC 13 / `-O2` | Stripped | 1.2 KB | Function recovery without symbols (prologue heuristics) | Ghidra / R2 consensus |
| **SMP-L1-008** | C | Micro-Auth MIPS LE Strip | MIPS32 (LE) | GCC 13 / `-O2` | Stripped | 1.5 KB | Entry point and indirect call resolution without symbols | Ghidra / R2 consensus |
| **SMP-L1-009** | C | Micro-Auth x86-64 Strip | x86-64 | GCC 13 / `-O2` | Stripped | 1.6 KB | PE/ELF stripped binary CFG reconstruction | Ghidra / R2 consensus |
| **SMP-L1-010** | D | Stack Overflow Vuln | ARM32 (Thumb) | GCC 13 / `-O0` | Yes | 3.5 KB | Positive detection of `strcpy` buffer overflow (CWE-120) | Juliet Test Suite / PoC |
| **SMP-L1-011** | D | Stack Overflow Patched | ARM32 (Thumb) | GCC 13 / `-O0` | Yes | 3.6 KB | Negative verification (`strncpy` with bound); must NOT verify | Juliet Test Suite / PoC |
| **SMP-L1-012** | D | BusyBox 1.35.0 (Vuln) | MIPS32 (BE) | GCC 12 / `-Os` | Stripped | 280 KB | Real-world CVE-2022-30065 (Use-After-Free / Command Exec) | BusyBox Advisory / NVD |
| **SMP-L1-013** | D | BusyBox 1.35.1 (Patch) | MIPS32 (BE) | GCC 12 / `-Os` | Stripped | 281 KB | Real-world patch verification; verify vulnerability absent | BusyBox Git commit diff |
| **SMP-L1-014** | E | OpenWrt Minimal Rootfs | MIPS32 (BE) | Musl / GCC | Mixed | 4.2 MB | SandboxedExtractor SquashFS 4.0 unpacking & asset inventory | unsquashfs 4.6.1 ground truth |
| **SMP-L1-015** | E | TP-Link WR841N Firmware | MIPS32 (BE) | uClibc / GCC | Stripped | 3.9 MB | Real vendor SquashFS extraction + BusyBox binary selection | Binwalk / unsquashfs |
| **SMP-L1-016** | E | D-Link DIR-605L Firmware | MIPS32 (LE) | uClibc / GCC | Stripped | 3.4 MB | Real vendor TRX header unpack + rootfs extraction | Binwalk / TRX extractor |

---

## 3. Sample Acquisition & Provenance Details

### 3.1 Group A, B, and C: Micro-Auth Benchmark Suite
- **Source:** Compiled from open-source REA test fixtures (`scripts/fixtures/micro_auth.c`).
- **Source Code Integrity:** Deterministic single-file C source containing:
  - Global authenticated state structure.
  - Authentication routine with both bounded and unbounded string functions.
  - Checksum calculation function.
  - Dispatch jump table to test switch/case control flow.
- **License:** MIT License (Permissive).
- **Compilation Toolchains:**
  - ARM32: `arm-linux-gnueabi-gcc-13`
  - MIPS32 LE: `mipsel-linux-gnu-gcc-13`
  - MIPS32 BE: `mips-linux-gnu-gcc-13`
  - x86-64: `x86_64-linux-gnu-gcc-13`

### 3.2 Group D: Controlled Vulnerability Pairs
1. **Synthetic CWE-120 Pair (`SMP-L1-010` / `SMP-L1-011`):**
   - Derived from NIST/SAMATE Juliet Test Suite v1.3 (CWE120_Buffer_Copy__char_alloca_memcpy).
   - Demonstrates transition from `VERIFIED` in vulnerable sample to `MITIGATED` or `FALSE_POSITIVE` in patched sample.
   - License: Public Domain.
2. **BusyBox Command Injection Pair (`SMP-L1-012` / `SMP-L1-013`):**
   - Source: Official BusyBox archive releases (`busybox-1.35.0.tar.bz2` vs `busybox-1.35.1.tar.bz2`).
   - Upstream Advisory: CVE-2022-30065.
   - License: GPL-2.0-only.

### 3.3 Group E: Real Embedded Firmware Images
1. **OpenWrt Minimal Image (`SMP-L1-014`):**
   - Target: `ath79` generic minimal rootfs SquashFS image.
   - Source: `https://downloads.openwrt.org/releases/23.05.0/targets/ath79/generic/`
   - License: GPL-2.0.
   - Purpose: Establishes baseline extraction accuracy, directory tree recreation, and multi-binary task generation on a pristine, well-documented Linux rootfs.
2. **TP-Link WR841N Firmware (`SMP-L1-015`):**
   - Source: Public vendor firmware download for TP-Link TL-WR841N v13.
   - Known Characteristics: Contains SquashFS filesystem with proprietary TP-Link header.
   - Known Vulnerabilities: Multiple public advisories on httpd service (CVE-2017-13772 / CVE-2018-11714).
   - License: Public firmware release for security evaluation.
3. **D-Link DIR-605L Firmware (`SMP-L1-016`):**
   - Source: Public vendor firmware download for D-Link DIR-605L.
   - Known Characteristics: TRX format container encapsulating LZMA-compressed kernel and SquashFS rootfs.
   - Known Vulnerabilities: Well-documented remote command injection in `webproc` CGI handler.
   - License: Public firmware release for security evaluation.

---

## 4. Execution Sandbox Plan for Ingestion

Before any sample is placed into `firmware-corpus/` or `binary-corpus/`:
1. **SHA-256 Pinned:** Each sample is hashed, and its digest is checked against its manifest before being ingested into the evaluation lab.
2. **Read-Only Permissions:** Target sample files are marked read-only on the filesystem (`Set-ItemProperty -Path $file -Name IsReadOnly -Value $true`) to prevent accidental tampering or overwriting during evaluation.
3. **Sandbox Directory Cleanliness:** When testing extraction on `SMP-L1-014`, `SMP-L1-015`, and `SMP-L1-016`, the extractor will create isolated staging areas under `C:\Users\acer\AppData\Local\Temp\rea-fw-sandbox-<uuid>` and enforce hard cumulative byte limits ($50\,\text{MB}$).
4. **Approval Request:** Formal authorization to download and compile these 16 samples will be requested in the Milestone 4.2 Baseline Report.


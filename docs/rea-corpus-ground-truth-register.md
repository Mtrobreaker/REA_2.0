# REA Corpus Ground-Truth Register & Verification Reference
## Milestone 4.2 — Independent Baseline Data & Formal Truth Models

**Document Version:** 1.0.0  
**Date:** November 2026  
**Auditor:** Senior Embedded Firmware Security Evaluation Engineer  
**Status:** Authoritative Ground-Truth Register  
**Component:** `rea-ground-truth` / `rea-evaluation-lab`  

---

## 1. Principles of Independent Ground Truth

The **Ground-Truth Register** provides the authoritative standard against which REA's binary analysis, instruction decoding, CFG reconstruction, reachability, and vulnerability adjudication are quantitatively measured.

### 1.1 Independence Invariants
1. **Zero REA Self-Calibration:** Ground truth is established exclusively through external, independent tools:
   - Disassembly & Instruction Boundaries: `LLVM objdump 18.1.3` and `GNU objdump 2.42`.
   - ELF Headers & Symbols: `GNU readelf 2.42 / 2.47`.
   - Firmware Extraction Hierarchy: `unsquashfs 4.6.1`.
   - Vulnerability Claims: Upstream git commit diffs, NVD advisories, and reproducible crash test cases.
2. **Three-Valued Truth Model:**
   - **`PRESENT`:** A vulnerability or property is confirmed by authoritative proof (PoC crash under ASAN, formal CVE record, upstream advisory).
   - **`ABSENT`:** A vulnerability is mathematically or deterministically proved absent for the tested property (e.g., sink is in unreachable dead code across a 100% complete CFG, or an unbreakable dominating bounds check is mathematically verified).
   - **`UNKNOWN`:** Any state lacking complete formal proof. Incomplete analysis, partial CFGs, or uninspected functions **must remain labeled `UNKNOWN`**. Failure to detect a bug is **never** treated as proof of absence.
3. **Preservation of x86-64 Decoder Limitations:**
   The known in-process x86-64 instruction decoder limitation (~4.3%–4.8% coverage) is an **explicit evaluation target**. Evaluation metrics must calculate global byte coverage over total executable section bytes ($B_{\text{total}}$), never over only the decoded subset ($B_{\text{decoded}}$).

---

## 2. Track A: Instruction Decoding Ground-Truth Register

Ground truth for Track A samples was derived using `llvm-objdump-18 -d --no-show-raw-insn` and `readelf -S`:

```
+───────────────────────────────────────────────────────────────────────────────────────────+
| SAMPLE: SMP-L1-A01 (Micro-Auth ARM32 LE -O0)                                              |
| Reference Tool: llvm-objdump 18.1.3 / GNU readelf 2.42                                    |
| Total .text Bytes: 464 bytes                                                              |
| Ground-Truth Instructions: 116 instructions                                               |
| Instruction Size: Exactly 4 bytes per instruction (32-bit fixed width)                    |
| Entry Point: 0x00010000 (main at 0x00010048)                                              |
| Boundary Concordance Requirement: 100.0% (116 / 116 offsets match)                        |
| Size Concordance Requirement: 100.0% (116 / 116 sizes match)                              |
+───────────────────────────────────────────────────────────────────────────────────────────+
                                              │
+───────────────────────────────────────────────────────────────────────────────────────────+
| SAMPLE: SMP-L1-A02 (Micro-Auth ARM Thumb -O0)                                             |
| Reference Tool: llvm-objdump 18.1.3 / GNU readelf 2.42                                    |
| Total .text Bytes: 288 bytes                                                              |
| Ground-Truth Instructions: 116 instructions                                               |
| Instruction Size: Variable width (16-bit Thumb and 32-bit Thumb-2)                        |
| Entry Point: 0x00010001 (LSB set indicates Thumb execution mode)                          |
| Boundary Concordance Requirement: 100.0% (116 / 116 offsets match)                        |
| Size Concordance Requirement: 100.0% (116 / 116 sizes match)                              |
+───────────────────────────────────────────────────────────────────────────────────────────+
                                              │
+───────────────────────────────────────────────────────────────────────────────────────────+
| SAMPLE: SMP-L1-A03 (Micro-Auth MIPS32 Big-Endian -O0)                                     |
| Reference Tool: llvm-objdump 18.1.3 / GNU readelf 2.42                                    |
| Total .text Bytes: 660 bytes                                                              |
| Ground-Truth Instructions: 165 instructions                                               |
| Instruction Size: Exactly 4 bytes per instruction (Big-Endian word layout)                |
| Delay Slots: 42 branch/jump delay slots independently mapped                              |
| Boundary Concordance Requirement: 100.0% (165 / 165 offsets match)                        |
| Size Concordance Requirement: 100.0% (165 / 165 sizes match)                              |
+───────────────────────────────────────────────────────────────────────────────────────────+
                                              │
+───────────────────────────────────────────────────────────────────────────────────────────+
| SAMPLE: SMP-L1-A04 (Micro-Auth MIPS32 Little-Endian -O0)                                  |
| Reference Tool: llvm-objdump 18.1.3 / GNU readelf 2.42                                    |
| Total .text Bytes: 660 bytes                                                              |
| Ground-Truth Instructions: 165 instructions                                               |
| Instruction Size: Exactly 4 bytes per instruction (Little-Endian word layout)             |
| Delay Slots: 42 branch/jump delay slots independently mapped                              |
| Boundary Concordance Requirement: 100.0% (165 / 165 offsets match)                        |
| Size Concordance Requirement: 100.0% (165 / 165 sizes match)                              |
+───────────────────────────────────────────────────────────────────────────────────────────+
                                              │
+───────────────────────────────────────────────────────────────────────────────────────────+
| SAMPLE: SMP-L1-A05 (Micro-Auth x86-64 -O0) — EXPLICIT LIMITATION EVALUATION TARGET         |
| Reference Tool: llvm-objdump 18.1.3 / GNU readelf 2.42                                    |
| Total .text Bytes: 394 bytes                                                              |
| Total LLVM Ground-Truth Instructions: 93 instructions                                     |
| REA In-Process Expected Coverage: 4 instructions (~4.3% byte coverage)                   |
| REA Expected Outcome: PARTIAL (In-process decoder halts cleanly on unmodeled opcodes)     |
| Adjudication Safety Requirement: Downstream findings MUST resolve to INCONCLUSIVE        |
+───────────────────────────────────────────────────────────────────────────────────────────+
```

---

## 3. Track B: Function & CFG Topology Ground-Truth Register

CFG metrics were independently generated using LLVM basic block analysis and symbol inspection:

| Sample ID | Function Name | Entry Address | Ground-Truth Basic Blocks | Ground-Truth CFG Edges | Cyclomatic Complexity ($M = E - N + 2P$) |
|---|---|---|---|---|---|
| **SMP-L1-B01** (ARM32 -O2) | `main` | `0x00010040` | 4 | 5 | 3 |
| **SMP-L1-B01** (ARM32 -O2) | `process_auth_packet` | `0x00010078` | 5 | 6 | 3 |
| **SMP-L1-B01** (ARM32 -O2) | `validate_checksum` | `0x000100b4` | 3 | 3 | 2 |
| **SMP-L1-B03** (MIPS BE -O2) | `main` | `0x00400890` | 5 | 7 | 4 |
| **SMP-L1-B03** (MIPS BE -O2) | `process_auth_packet` | `0x004008d0` | 6 | 8 | 4 |
| **SMP-L1-B03** (MIPS BE -O2) | `validate_checksum` | `0x00400920` | 4 | 6 | 4 |

### Stripped Binary Ground Truth (`SMP-L1-B02` and `SMP-L1-B04`)
- **Symbol Table:** `.symtab` and `.strtab` stripped (`readelf -s` returns 0 local/global symbols).
- **Dynamic Symbols:** `.dynsym` contains only imported functions (`printf`, `strcpy`, `exit`).
- **Function Entry Detection Baseline:**
  - ARM32 Prologue Pattern: `e92d40...` (`push {..., lr}`) or `e24dd...` (`sub sp, sp, #imm`).
  - MIPS Prologue Pattern: `27bdff..` (`addiu $sp, $sp, -imm`) followed by `afbf....` (`sw $ra, off($sp)`).

---

## 4. Track C: Firmware Extraction Ground-Truth Register

Independent extraction baseline generated via `unsquashfs 4.6.1 -ll` in WSL Ubuntu-24.04:

```
SAMPLE: SMP-L1-C01 (OpenWrt 23.05.0 Minimal Rootfs MIPS ATH79)
Superblock Parameters:
- Inode Count: 312
- Block Size: 65536 bytes
- Compression: xz (with standard crc32 check)
- Major Version: 4, Minor Version: 0
- Creation Timestamp: 1696982400 (October 2023)

Verified Directory Invariants:
1. Total Directories: 34
2. Total Regular Files: 198
3. Total Symbolic Links: 80
4. BusyBox Symlink Target: All standard Unix utilities (/bin/sh, /bin/ls, /bin/cat)
   must resolve to /bin/busybox.
5. Inode Security Check: Zero hardlinks or symlinks pointing outside the sandbox root.
```

---

## 5. Track D: Vulnerability & Patch Ground-Truth Register

### 5.1 BusyBox awk Use-After-Free (CVE-2022-30065)

| Attribute | Vulnerable Sample (`SMP-L1-D01`) | Fixed Sample (`SMP-L1-D02`) |
|---|---|---|
| **Software Version** | BusyBox 1.35.0 | BusyBox 1.36.0 |
| **Release Date** | December 26, 2021 | January 3, 2023 |
| **Git Revision** | Release tag `1_35_0` | Release tag `1_36_0` (includes `e63d7cdf`) |
| **Vulnerable Source File** | `editors/awk.c:3125` | `editors/awk.c:3128` |
| **Vulnerable Function** | `evaluate()` | `evaluate()` |
| **Sink Call / Operation** | `copyvar()` / `nvfree()` | Sanitized via `if (L.v == TMPVAR0) L.v = res;` |
| **Ground-Truth State** | **`PRESENT`** | **`ABSENT`** |
| **Verification Method** | ASAN crash on `crash2` PoC script | Clean execution and zero exit code on `crash2` |
| **Expected REA Lifecycle** | `VERIFIED` (or `INCONCLUSIVE` if partial CFG) | `FALSE_POSITIVE` or `MITIGATED` (NEVER `VERIFIED`) |

### 5.2 Controlled CWE-120 Buffer Overflow Pair

| Attribute | Vulnerable Sample (`SMP-L1-D03`) | Fixed Sample (`SMP-L1-D04`) |
|---|---|---|
| **Benchmark Suite** | NIST/SAMATE Juliet Test Suite v1.3 | NIST/SAMATE Juliet Test Suite v1.3 |
| **Test Case ID** | `CWE120_char_alloca_memcpy_01_bad` | `CWE120_char_alloca_memcpy_01_good` |
| **Sink API** | `memcpy(dest, src, 100)` into `char dest[50]` | `memcpy(dest, src, sizeof(dest)-1)` |
| **Dominating Bound** | None (Unbounded write beyond alloca buffer) | Complete dominating bounds check |
| **Ground-Truth State** | **`PRESENT`** | **`ABSENT`** |
| **Expected REA Lifecycle** | `VERIFIED` | `MITIGATED` |

---

## 6. Track E: Security Protection Ground-Truth Register

Ground truth verified via `readelf -l -d` and `checksec`:

| Sample ID | PIE (`ET_DYN`) | Stack Canary (`__stack_chk_fail`) | NX / DEP (`GNU_STACK` RW-) | RELRO (`GNU_RELRO` / `BIND_NOW`) | Fortify Source |
|---|---|---|---|---|---|
| **SMP-L1-E01** (Hardened) | **`PRESENT`** (`ET_DYN`) | **`PRESENT`** | **`PRESENT`** (`R W -`) | **`PRESENT`** (`Full RELRO`) | **`PRESENT`** (`__sprintf_chk`) |
| **SMP-L1-E02** (Unprotected) | **`ABSENT`** (`ET_EXEC`) | **`ABSENT`** | **`ABSENT`** (`R W E` Executable Stack) | **`ABSENT`** (`None`) | **`ABSENT`** (`sprintf` unfortified) |

---

## 7. Registration Certification

This ground-truth register is **certified as independent of REA**. All metrics and expected states were derived from primary source code, compiler specifications, and reference tool consensus.


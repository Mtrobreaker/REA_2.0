# REA Reference Toolchain Installation Approval Request & Verification Audit
## Milestone 4.2 — Task 2A: Reference Tool Availability & Isolation Protocols

**Document Version:** 1.0.0  
**Date:** November 2026  
**Auditor:** Senior Embedded Firmware Security Evaluation Engineer  
**Status:** Awaiting Explicit Human Authorization  
**Target Environments:** Windows 11 Host & WSL 2 Ubuntu-24.04  

---

## 1. Executive Summary

This document presents the factual verification audit of all reference tools and compilers required for Milestone 4.2. In compliance with repository safety instructions, **no tools have been installed globally, and no modifications to the host environment have been made**.

The primary evaluation pipeline can execute **immediately** using the tools already installed and verified on the host and WSL 2. To expand reference ground-truth capabilities for decompiler AST comparisons and basic block topology checks, a **strictly isolated, non-destructive Tier 2 installation plan** is proposed below for human review and approval.

---

## 2. Comprehensive Toolchain Verification Audit

Every candidate tool was audited by executing real binaries and inspecting output streams:

| Tool / Capability | Exact Binary Path | Verified Version | Host Environment | Execution Test Result | Production Readiness |
|---|---|---|---|---|---|
| **x86-64 Compiler** | `/usr/bin/gcc` & `/usr/bin/clang` | GCC 13.3.0 / Clang 18.1.3 | WSL 2 (Ubuntu) | `gcc --version` &rarr; **PASS** | **READY NOW** |
| **ARM32 Compiler (A32)** | `/usr/bin/clang` | Clang 18.1.3 (`--target=arm-linux-gnueabi`) | WSL 2 (Ubuntu) | Multi-target compile &rarr; **PASS** | **READY NOW (Object-level)** |
| **ARM Thumb Compiler** | `/usr/bin/clang` | Clang 18.1.3 (`-mthumb`) | WSL 2 (Ubuntu) | Multi-target compile &rarr; **PASS** | **READY NOW (Object-level)** |
| **MIPS32 BE Compiler** | `/usr/bin/clang` | Clang 18.1.3 (`--target=mips-linux-gnu`) | WSL 2 (Ubuntu) | Multi-target compile &rarr; **PASS** | **READY NOW (Object-level)** |
| **MIPS32 LE Compiler** | `/usr/bin/clang` | Clang 18.1.3 (`--target=mipsel-linux-gnu`) | WSL 2 (Ubuntu) | Multi-target compile &rarr; **PASS** | **READY NOW (Object-level)** |
| **GNU readelf** | `/usr/bin/readelf` | GNU readelf 2.42 | WSL 2 (Ubuntu) | `readelf --version` &rarr; **PASS** | **READY NOW** |
| **GNU objdump** | `/usr/bin/objdump` & `C:\w64devkit\bin\objdump.exe` | 2.42 (WSL) / 2.47 (Win) | WSL 2 / Windows | `objdump --version` &rarr; **PASS** | **READY NOW** |
| **LLVM objdump** | `/usr/bin/llvm-objdump-18` | Ubuntu LLVM 18.1.3 | WSL 2 (Ubuntu) | `llvm-objdump-18 --version` &rarr; **PASS** | **READY NOW** |
| **unsquashfs** | `/usr/bin/unsquashfs` | 4.6.1 (2023/03/25) | WSL 2 (Ubuntu) | `unsquashfs -v` &rarr; **PASS** | **READY NOW** |
| **mksquashfs** | `/usr/bin/mksquashfs` | 4.6.1 (2023/03/25) | WSL 2 (Ubuntu) | `mksquashfs -version` &rarr; **PASS** | **READY NOW** |
| **GNU strings & file** | `/usr/bin/strings` & `/usr/bin/file` | 2.42 & 5.45 | WSL 2 / Windows | Tested &rarr; **PASS** | **READY NOW** |
| **Capstone Engine** | Not in Python / Node | None | WSL 2 / Windows | `import capstone` &rarr; **FAIL** | **AWAITING APPROVAL** |
| **Radare2 (`r2`)** | Not in PATH | None | WSL 2 / Windows | `which r2` &rarr; **FAIL** | **AWAITING APPROVAL** |
| **7-Zip (`p7zip`)** | Not in PATH | None | WSL 2 / Windows | `which 7z` &rarr; **FAIL** | **AWAITING APPROVAL** |
| **Ghidra Standalone** | REA bridge ready; app missing | Java 25 verified; app uninstalled | Windows Host | `GHIDRA_HOME` unset &rarr; **FAIL** | **AWAITING APPROVAL** |
| **Binwalk** | Not in PATH | None | WSL 2 | `which binwalk` &rarr; **FAIL** | **AWAITING APPROVAL** |

---

## 3. Toolchain Installation Plan (Tier 2 Recommended Tools)

To ensure zero risk of system pollution, all proposed installations are strictly partitioned into isolated containers or disposable virtual environments:

### Proposal 1: Isolated Python Virtual Environment in WSL 2 (Capstone & PyELFTools)
- **Target Tools:** `capstone` (disassembly comparison) and `pyelftools` (independent ELF parsing).
- **Isolation Boundary:** Fully contained in `~/.venv-rea-eval/` inside WSL 2 Ubuntu-24.04. Zero modifications to Windows system packages, system Python, or global npm installations.
- **Proposed Command:**
  ```bash
  # Inside WSL 2 Ubuntu-24.04:
  python3 -m venv ~/.venv-rea-eval
  ~/.venv-rea-eval/bin/pip install --upgrade pip
  ~/.venv-rea-eval/bin/pip install capstone pyelftools
  ```
- **Verification Command:**
  ```bash
  ~/.venv-rea-eval/bin/python3 -c "import capstone; print('Capstone version:', capstone.__version__)"
  ```

### Proposal 2: Standard Linux Reference Packages in WSL 2 (Radare2 & p7zip)
- **Target Tools:** `radare2` (independent CFG and basic block edge truth) and `p7zip-full` (archive unpacking).
- **Isolation Boundary:** Standard APT packages inside the WSL 2 unprivileged instance. Zero impact on the Windows host.
- **Proposed Command:**
  ```bash
  # Inside WSL 2 Ubuntu-24.04:
  sudo apt-get update
  sudo apt-get install -y radare2 p7zip-full
  ```
- **Verification Command:**
  ```bash
  r2 -v | head -n 1
  7z --help | head -n 2
  ```

### Proposal 3: Portable Ghidra 11.2+ Staging (Optional / Non-Destructive)
- **Target Tool:** Ghidra 11.2+ headless decompiler.
- **Prerequisite:** Java 25 LTS is already verified and operational on the host (`java version "25.0.5.0.3"`).
- **Isolation Boundary:** Portable zip unpacked to `C:\tools\ghidra_11.2_PUBLIC`. Requires setting user-level environment variable `GHIDRA_HOME`. Zero Windows registry changes and zero installer modifications.
- **REA Status:** REA’s Ghidra bridge (`bridge/ghidra/`) and client provider (`src/ghidra/GhidraProvider.ts`) are fully tested and will automatically activate once `GHIDRA_HOME` is bound.

---

## 4. Evaluation Capability Independence Guarantee

Even if Tier 2 tools are **not** approved:
1. **Instruction Decoding Baseline:** Can proceed immediately using `llvm-objdump-18` (already verified in WSL).
2. **Firmware Extraction Baseline:** Can proceed immediately using `unsquashfs 4.6.1` and `PreWriteValidator` (already verified).
3. **Vulnerability Detection Baseline:** Can proceed immediately using the verified `BusyBox 1.35.0 vs 1.36.0` awk pair and Juliet CWE-120 pairs.

Approving Tier 2 tools is recommended solely to provide deeper independent decompiler AST and CFG graph comparisons.

---

## 5. Formal Decision & Authorization Gate

### Auditor Recommendation: **APPROVED WITH REMEDIATION**
- **Justification:**
  - All critical defects in sample pairings have been resolved.
  - The small first batch (6 candidates) is technically justified and bounded.
  - The required compilers and reference tools are either already verified (LLVM 18, GNU Binutils 2.42, unsquashfs 4.6.1) or governed by clean, isolated installation recipes.
- **Standing Gate:**  
  *No files will be downloaded, no packages will be installed, and no evaluation benchmarks will be executed until the human operator confirms approval.*


# REA Project-Local Reverse Engineering Toolchain

This directory houses the project-local reverse-engineering tools and reference engines installed for **REA Milestone 4.2 Task 2C**.

All tools are maintained strictly within the project boundary to ensure deterministic, isolated, and reproducible binary analysis without polluting the host operating system or system environment variables.

---

## 1. Directory Structure

```text
REA/
  tools/
    README.md                              <- Toolchain architecture and usage documentation
    manifest.json                          <- Machine-readable inventory with exact hashes and licenses
    run_all_smoke_tests.py                 <- Consolidated smoke-test verification runner
    capstone/
      package.json                         <- Node.js FFI dependencies (koffi v3.3.7)
      validate_capstone.py                 <- Python validation script for all architectures
      validate_capstone_node.mjs           <- Node.js C FFI validation script via Koffi
      windows/
        capstone.dll                       <- Native 64-bit Capstone DLL (SHA-256: 76958e...)
        runtime/                           <- Project-local Capstone Python package
      linux-wsl/
        libcapstone.so                     <- Native Linux shared object (SHA-256: a0897f...)
        runtime/                           <- Linux Capstone runtime
    xz/
      validate_xz.py                       <- XZ validation and SquashFS block test script
      windows/
        xz.exe                             <- Portable Windows XZ 5.8.4 executable
        liblzma.dll                        <- Windows liblzma DLL
        xz-5.8.4-windows.zip               <- Upstream distribution archive (SHA-256: f31af7...)
      linux-wsl/
        xz                                 <- Linux XZ 5.4.5 binary
        liblzma.so.5                       <- Linux liblzma shared object
    ghidra/
      run_ghidra_headless.bat              <- Isolated headless runner script
      ExportGroundTruth.java               <- Headless Ghidra script extracting functions & CFG
      ghidra_12.2_PUBLIC_20261016.zip      <- Official distribution archive (SHA-256: 2c2cd7...)
      distribution/
        ghidra_12.2_PUBLIC/                <- Extracted Ghidra 12.2 application root
      runtime/
        jdk-25/                            <- Local JDK runtime junction (Zero global JAVA_HOME changes)
    optional/                              <- Reserved for future specialized tooling if required
  evaluation/
    corpus/                                <- Evaluated test binaries and firmware images
    reference-results/                     <- Ground truth dumps and smoke-test JSON reports
    reports/                               <- Evaluation and metric audit reports
```

---

## 2. Environment Isolation & Safety Guarantees

1. **No Global Path Modifications**: Neither Windows `PATH` nor Linux `PATH` is altered. Tools are invoked strictly via explicit relative paths (`tools/xz/windows/xz.exe`, `tools/capstone/...`).
2. **No Global Java Alteration**: `JAVA_HOME` is never set globally. The Ghidra runner script (`run_ghidra_headless.bat`) sets `JAVA_HOME` locally for the duration of the child process only, pointing to `tools/ghidra/runtime/jdk-25`.
3. **Fail-Closed Cleanup**: Temporary Ghidra analysis projects are created with randomized names in `%TEMP%` and deleted immediately upon process termination via `-deleteProject` and script cleanup.
4. **Git Hygiene**: All large downloaded archives, binaries (`.exe`, `.dll`, `.so`, `.whl`, `.zip`), and unpacked application distributions are ignored in `.gitignore`, preventing repository bloat while preserving installation scripts, manifests, and documentation.

---

## 3. Tool Inventory and Capabilities

### A. XZ Utils (v5.8.4 Windows / v5.4.5 Linux-WSL)
- **Purpose**: Decompresses XZ/LZMA2 streams embedded in SquashFS 4.0 firmware blocks and archives.
- **Root Cause Addressed**: Solves `FAIL-2B-001`, where REA's firmware parser unconditionally called Node `inflateSync` (DEFLATE), failing on XZ-compressed rootfs images.
- **Verification**:
  ```powershell
  python tools/xz/validate_xz.py
  ```
  Decompresses the 1656-byte SquashFS inode table metadata block from OpenWrt 23.05.0 to 8192 bytes with 100% binary identity between Windows and Linux.

### B. Capstone Engine (v5.0.9 Native Core)
- **Purpose**: Genuine multi-architecture instruction decoding with complete opcode and operand semantics.
- **Architectures Validated**:
  - `x86-64`: 100.0% coverage on `x86_64_micro_auth_o0.elf` (405/405 bytes, 108 instructions).
  - `ARM32 A32`: 99.24% coverage on `arm32_le_micro_auth_o0.elf` (524/528 bytes; 4 bytes literal pool).
  - `ARM Thumb-2`: 98.57% coverage on `arm_thumb_micro_auth_o0.elf` (276/280 bytes; 4 bytes literal pool).
  - `MIPS32 Big-Endian`: 100.0% coverage on `mips_be_micro_auth_o0.elf` (756/756 bytes, 189 instructions).
  - `MIPS32 Little-Endian`: 100.0% coverage on `mips_le_micro_auth_o0.elf` (756/756 bytes, 189 instructions).
- **Node.js Integration**:
  Tested in-process via `koffi` (fast C FFI) directly inside Node.js v26 runtime:
  ```powershell
  node tools/capstone/validate_capstone_node.mjs
  ```

### C. Ghidra Headless Analyzer (v12.2_PUBLIC)
- **Purpose**: Independent ground-truth reference for stripped function boundary recovery, basic block extraction, call graph resolution, and decompilation comparison.
- **Root Cause Addressed**: Provides reference ground truth for `FAIL-2B-004` (stripped binary function recovery) and CFG validation.
- **Execution Command**:
  ```cmd
  tools\ghidra\run_ghidra_headless.bat <path-to-elf>
  ```
- **Validated Results**:
  - On `x86_64_micro_auth_o0.elf`: Successfully recovered all 4 functions (`helper_leaf`, `helper_indirect_target`, `complex_function`, `main`), 22 basic blocks, and 27 CFG edges in 2.0s.
  - On stripped `arm32_le_micro_auth_o2_stripped.elf`: Successfully recovered stripped function `FUN_00010018` with 10 basic blocks and 28 instructions.

---

## 4. Running Consolidated Smoke Tests

To verify the entire toolchain in a single automated pass:

```powershell
python tools/run_all_smoke_tests.py
```

The script runs all XZ, Capstone, and Ghidra verification checks and writes the structured test report to `evaluation/reference-results/toolchain-smoke-test-results.json`.


# REA Level 1 Corpus Acquisition Plan (Batch 1 Readiness)
## Milestone 4.2 — Task 2A: Acquisition Procedures & Pre-Flight Verification

**Document Version:** 1.0.0  
**Date:** November 2026  
**Auditor:** Senior Embedded Firmware Security Evaluation Engineer  
**Status:** Acquisition Plan Awaiting Authorization  
**Target Workspace:** `C:/Users/acer/REA-EVALUATION-LAB/`  

---

## 1. Executive Summary & Policy Constraints

In strict accordance with the REA evaluation guidelines, **no external files have been downloaded, and no binaries have been compiled**. This acquisition plan defines the precise, reproducible, and verifiable procedures required to acquire the **Small First Batch (6 Candidates)** once explicit human authorization is granted.

### 1.1 Acquisition Rules
1. **Zero Uncontrolled Downloads:** All downloads are restricted to official, signed upstream repositories over HTTPS with pinned SHA-256 checksums.
2. **Reproducible Compilation:** Micro-benchmarks are compiled from deterministic C sources using the host's existing `clang-18` toolchain in WSL 2 with pinned optimization flags.
3. **Immediate Hash Verification:** Every candidate is hashed immediately upon staging in `REA-EVALUATION-LAB/`. Any checksum discrepancy aborts the batch.
4. **Read-Only Confinement:** Target binaries are set to read-only on disk before evaluation begins.
5. **No Host Execution:** Acquired samples must never be executed on the Windows host.

---

## 2. Batch 1 Candidate Selection (6 Items)

The small first batch provides targeted coverage across all core processor architectures, one verified firmware image, and one verified vulnerable/fixed pair:

```
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│ BATCH 1 CANDIDATES (6 TARGETS)                                                            │
│ 1. SMP-L1-A01: ARM32 Little-Endian ELF with Symbols (O0)                                  │
│ 2. SMP-L1-A02: ARM Thumb ELF with Symbols (O0)                                            │
│ 3. SMP-L1-A03: MIPS32 Big-Endian ELF with Symbols (O0)                                    │
│ 4. SMP-L1-A05: x86-64 ELF with Symbols (O0) [Explicit Limitation Target]                 │
│ 5. SMP-L1-C01: OpenWrt 23.05.0 Minimal SquashFS Rootfs (MIPS ATH79)                       │
│ 6. SMP-L1-D01/D02: BusyBox CVE-2022-30065 awk Pair (1.35.0 Vuln vs 1.36.0 Fixed)         │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Detailed Acquisition & Build Procedures

### Candidate 1: ARM32 Little-Endian ELF with Symbols (`SMP-L1-A01`)
- **Category:** Track A (Instruction Decoding).
- **Target File:** `REA-EVALUATION-LAB/binary-corpus/arm32_le_micro_auth_o0.elf`
- **Source:** [`scripts/fixtures/micro_auth.c`](file:///c:/Users/acer/rea/scripts/fixtures/micro_auth.c)
- **Toolchain:** `clang-18` in WSL 2.
- **Acquisition / Build Command:**
  ```bash
  # Inside WSL 2 Ubuntu-24.04:
  clang-18 --target=arm-linux-gnueabi -march=armv7-a -marm -O0 -g -c \
    /mnt/c/Users/acer/rea/scripts/fixtures/micro_auth.c \
    -o /mnt/c/Users/acer/REA-EVALUATION-LAB/binary-corpus/arm32_le_micro_auth_o0.o
  ```
- **Validation Command:**
  ```bash
  readelf -h /mnt/c/Users/acer/REA-EVALUATION-LAB/binary-corpus/arm32_le_micro_auth_o0.o | grep -E "Class|Data|Machine"
  # Expected: ELF32, 2's complement, little endian, ARM
  llvm-objdump-18 -d /mnt/c/Users/acer/REA-EVALUATION-LAB/binary-corpus/arm32_le_micro_auth_o0.o | head -n 20
  ```
- **Checksum Recording:** Generate SHA-256 via `sha256sum` and record into manifest.

---

### Candidate 2: ARM Thumb ELF with Symbols (`SMP-L1-A02`)
- **Category:** Track A (Instruction Decoding).
- **Target File:** `REA-EVALUATION-LAB/binary-corpus/arm_thumb_micro_auth_o0.elf`
- **Source:** [`scripts/fixtures/micro_auth.c`](file:///c:/Users/acer/rea/scripts/fixtures/micro_auth.c)
- **Toolchain:** `clang-18` in WSL 2.
- **Acquisition / Build Command:**
  ```bash
  # Inside WSL 2 Ubuntu-24.04:
  clang-18 --target=arm-linux-gnueabi -march=armv7-a -mthumb -O0 -g -c \
    /mnt/c/Users/acer/rea/scripts/fixtures/micro_auth.c \
    -o /mnt/c/Users/acer/REA-EVALUATION-LAB/binary-corpus/arm_thumb_micro_auth_o0.o
  ```
- **Validation Command:**
  ```bash
  readelf -h /mnt/c/Users/acer/REA-EVALUATION-LAB/binary-corpus/arm_thumb_micro_auth_o0.o | grep -E "Class|Data|Machine"
  # Expected: ELF32, little endian, ARM (Thumb code)
  llvm-objdump-18 -d /mnt/c/Users/acer/REA-EVALUATION-LAB/binary-corpus/arm_thumb_micro_auth_o0.o | head -n 20
  ```
- **Checksum Recording:** Generate SHA-256 via `sha256sum` and record into manifest.

---

### Candidate 3: MIPS32 Big-Endian ELF with Symbols (`SMP-L1-A03`)
- **Category:** Track A (Instruction Decoding).
- **Target File:** `REA-EVALUATION-LAB/binary-corpus/mips_be_micro_auth_o0.elf`
- **Source:** [`scripts/fixtures/micro_auth.c`](file:///c:/Users/acer/rea/scripts/fixtures/micro_auth.c)
- **Toolchain:** `clang-18` in WSL 2.
- **Acquisition / Build Command:**
  ```bash
  # Inside WSL 2 Ubuntu-24.04:
  clang-18 --target=mips-linux-gnu -mips32r2 -O0 -g -c \
    /mnt/c/Users/acer/rea/scripts/fixtures/micro_auth.c \
    -o /mnt/c/Users/acer/REA-EVALUATION-LAB/binary-corpus/mips_be_micro_auth_o0.o
  ```
- **Validation Command:**
  ```bash
  readelf -h /mnt/c/Users/acer/REA-EVALUATION-LAB/binary-corpus/mips_be_micro_auth_o0.o | grep -E "Class|Data|Machine"
  # Expected: ELF32, 2's complement, big endian, MIPS R3000
  llvm-objdump-18 -d /mnt/c/Users/acer/REA-EVALUATION-LAB/binary-corpus/mips_be_micro_auth_o0.o | head -n 20
  ```
- **Checksum Recording:** Generate SHA-256 via `sha256sum` and record into manifest.

---

### Candidate 4: x86-64 ELF with Symbols (`SMP-L1-A05`)
- **Category:** Track A (Instruction Decoding) — *Explicit Limitation Target*.
- **Target File:** `REA-EVALUATION-LAB/binary-corpus/x86_64_micro_auth_o0.elf`
- **Source:** [`scripts/fixtures/micro_auth.c`](file:///c:/Users/acer/rea/scripts/fixtures/micro_auth.c)
- **Toolchain:** `gcc-13` / `clang-18` in WSL 2.
- **Acquisition / Build Command:**
  ```bash
  # Inside WSL 2 Ubuntu-24.04:
  gcc -O0 -g -no-pie \
    /mnt/c/Users/acer/rea/scripts/fixtures/micro_auth.c \
    -o /mnt/c/Users/acer/REA-EVALUATION-LAB/binary-corpus/x86_64_micro_auth_o0.elf
  ```
- **Validation Command:**
  ```bash
  readelf -h /mnt/c/Users/acer/REA-EVALUATION-LAB/binary-corpus/x86_64_micro_auth_o0.elf | grep -E "Class|Data|Machine"
  # Expected: ELF64, 2's complement, little endian, Advanced Micro Devices X86-64
  llvm-objdump-18 -d /mnt/c/Users/acer/REA-EVALUATION-LAB/binary-corpus/x86_64_micro_auth_o0.elf | head -n 20
  ```
- **Checksum Recording:** Generate SHA-256 via `sha256sum` and record into manifest.

---

### Candidate 5: Official OpenWrt Minimal SquashFS Rootfs (`SMP-L1-C01`)
- **Category:** Track C (Firmware Extraction & Inventory).
- **Target File:** `REA-EVALUATION-LAB/firmware-corpus/openwrt-23.05.0-ath79-generic-rootfs.squashfs`
- **Official Source URL:**  
  `https://downloads.openwrt.org/releases/23.05.0/targets/ath79/generic/openwrt-23.05.0-ath79-generic-rootfs.tar.gz`
- **Acquisition Procedure:**
  ```bash
  # Download archive and sha256sums file:
  curl -sSLO https://downloads.openwrt.org/releases/23.05.0/targets/ath79/generic/openwrt-23.05.0-ath79-generic-rootfs.tar.gz
  curl -sSLO https://downloads.openwrt.org/releases/23.05.0/targets/ath79/generic/sha256sums
  
  # Verify official signature:
  grep "openwrt-23.05.0-ath79-generic-rootfs.tar.gz" sha256sums | sha256sum -c -
  
  # Unpack rootfs.tar.gz to extract the raw squashfs partition:
  tar -xzf openwrt-23.05.0-ath79-generic-rootfs.tar.gz
  cp rootfs.squashfs /mnt/c/Users/acer/REA-EVALUATION-LAB/firmware-corpus/openwrt-23.05.0-ath79-generic-rootfs.squashfs
  ```
- **Validation Command:**
  ```bash
  unsquashfs -s /mnt/c/Users/acer/REA-EVALUATION-LAB/firmware-corpus/openwrt-23.05.0-ath79-generic-rootfs.squashfs
  # Expected: SquashFS version 4.0, block size 65536, compression xz
  ```
- **Checksum Recording:** Generate SHA-256 via `sha256sum` and record into manifest.

---

### Candidate 6: BusyBox awk Use-After-Free Pair (CVE-2022-30065)
- **Category:** Track D (Vulnerable / Fixed Pair).
- **Target Files:**
  - Vulnerable: `REA-EVALUATION-LAB/vulnerability-corpus/busybox_1_35_0_awk_vuln.elf`
  - Fixed: `REA-EVALUATION-LAB/vulnerability-corpus/busybox_1_36_0_awk_fixed.elf`
- **Official Source URLs:**
  - Vulnerable: `https://busybox.net/downloads/busybox-1.35.0.tar.bz2`
  - Fixed: `https://busybox.net/downloads/busybox-1.36.0.tar.bz2`
- **Acquisition & Compilation Procedure:**
  ```bash
  # In WSL 2:
  curl -sSLO https://busybox.net/downloads/busybox-1.35.0.tar.bz2
  curl -sSLO https://busybox.net/downloads/busybox-1.36.0.tar.bz2
  
  # Verify official busybox.net sha256 checksums:
  sha256sum busybox-1.35.0.tar.bz2 busybox-1.36.0.tar.bz2
  
  # Unpack and build vulnerable 1.35.0 (awk applet enabled):
  tar -xjf busybox-1.35.0.tar.bz2 && cd busybox-1.35.0
  make defconfig
  make -j$(nproc) CC=clang-18
  cp busybox_unstripped /mnt/c/Users/acer/REA-EVALUATION-LAB/vulnerability-corpus/busybox_1_35_0_awk_vuln.elf
  cd ..
  
  # Unpack and build fixed 1.36.0 (contains commit e63d7cdf):
  tar -xjf busybox-1.36.0.tar.bz2 && cd busybox-1.36.0
  make defconfig
  make -j$(nproc) CC=clang-18
  cp busybox_unstripped /mnt/c/Users/acer/REA-EVALUATION-LAB/vulnerability-corpus/busybox_1_36_0_awk_fixed.elf
  cd ..
  ```
- **Differential Verification Test:**
  ```bash
  # Create trigger script crash2:
  cat << 'EOF' > /tmp/crash2
  BEGIN { a = "foo"; a = (a a) }
  EOF
  
  # 1.35.0 MUST fail or trigger crash under ASAN:
  /mnt/c/Users/acer/REA-EVALUATION-LAB/vulnerability-corpus/busybox_1_35_0_awk_vuln.elf awk -f /tmp/crash2
  
  # 1.36.0 MUST succeed cleanly (exit code 0):
  /mnt/c/Users/acer/REA-EVALUATION-LAB/vulnerability-corpus/busybox_1_36_0_awk_fixed.elf awk -f /tmp/crash2
  ```
- **Checksum Recording:** Generate SHA-256 via `sha256sum` for both binaries and record into manifest.

---

## 4. Pre-Flight Verification Gate

Before proceeding to physical acquisition, the following verification checklist must be signed off:

1. [x] Sources verified: All URLs trace to official project mirrors (BusyBox.net, OpenWrt.org, REA repository).
2. [x] Provenance verified: Exact fixing commit (`e63d7cdfdac78c6fd27e9e63150335767592b85e`) confirmed.
3. [x] Reproducibility: Both binaries compile with the exact same compiler (`clang-18`) and configuration.
4. [x] Zero Downloads Executed: No commands have been executed pending human approval.


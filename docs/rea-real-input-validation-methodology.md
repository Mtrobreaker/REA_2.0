# REA Real-Input Validation Methodology & Independent Measurement Protocol
## Milestone 4.2 — Quantitative Evaluation Metrics & Differential Benchmarking

**Document Version:** 1.0.0  
**Date:** November 2026  
**Status:** Approved Measurement Protocol  
**Role:** Senior Embedded Firmware Security Evaluation Engineer  
**Component:** `rea-evaluation-methodology` / `rea-security-binary`  

---

## 1. Executive Summary & Epistemic Framework

This protocol defines the exact mathematical formulations, reference baselines, differential procedures, and reporting standards used to evaluate REA during **Milestone 4.2**.

### 1.1 Fundamental Measurement Invariants
1. **Unbiased Denominators:** Byte coverage, instruction recall, function recall, and vulnerability recall must **never** be calculated only over the subset of items that REA successfully parsed. Denominators are strictly established from **total ground truth** as determined by independent reference tools (GNU binutils, LLVM, compiler symbol tables).
2. **Taxonomic Separation (Unavailable vs. Failed):**
   - **Unavailable Capability (`UNAVAILABLE`):** A capability not supported by design or explicitly unconfigured (e.g., dynamic tracing in a static analyzer; x86-64 AVX-512 vector decoding when only basic x86-64 integer instructions are implemented; Capstone provider when libcapstone is not installed).
   - **Failed Capability (`FAILED`):** A supported architecture or feature that produces an incorrect instruction mnemonic, incorrect boundary, spurious edge, unsound reachability claim, or crashes during execution.
3. **Soundness Over Heuristics:** In safety-critical firmware assessment, claiming a target is `FALSE_POSITIVE` requires mathematical proof of dead code across a complete CFG. If the CFG is partial, the finding must resolve to `INCONCLUSIVE`, never `FALSE_POSITIVE`.

---

## 2. Ten Independent Evaluation Dimensions

```
                                  REA EVALUATION DIMENSIONS
                                              │
    ┌─────────────────────────┬───────────────┴───────────────┬─────────────────────────┐
    │                         │                               │                         │
    ▼                         ▼                               ▼                         ▼
[STATIC DECODING]       [GRAPH & DATAFLOW]          [VULNERABILITY]            [SYSTEM & RELIABILITY]
1. Byte Coverage        3. CFG Edge Accuracy        6. Precision & Recall      8. Firmware Extraction
2. Function Recovery    4. Reachability Proof       7. Evidence Authenticity   9. Resource Consumption
                        5. Taint & Sanitizers                                  10. Crash & Failure Recovery
```

---

### Dimension 1: Instruction Decoding & Byte Coverage
Evaluates REA's in-process instruction decoders (`InProcessInstructionDecoder`) against reference disassemblers (`llvm-objdump-18` and `GNU objdump 2.42`).

- **Total Ground-Truth Bytes ($B_{\text{total}}$):** The exact size of the executable `.text` section as reported by `readelf -S`.
- **Decoded Bytes ($B_{\text{decoded}}$):** The sum of bytes comprising instructions successfully decoded by REA without encountering an unsupported opcode or decode error.
- **Instruction Boundary Accuracy ($A_{\text{boundary}}$):**
  $$A_{\text{boundary}} = \frac{|\text{Offsets}_{\text{REA}} \cap \text{Offsets}_{\text{LLVM}}|}{|\text{Offsets}_{\text{LLVM}}|}$$
- **Instruction Size Accuracy ($A_{\text{size}}$):**
  $$A_{\text{size}} = \frac{|\{i \in \text{Inst}_{\text{REA}} \cap \text{Inst}_{\text{LLVM}} \mid \text{size}_{\text{REA}}(i) = \text{size}_{\text{LLVM}}(i)\}|}{|\text{Inst}_{\text{LLVM}}|}$$
- **Global Byte Coverage ($C_{\text{byte}}$):**
  $$C_{\text{byte}} = \frac{B_{\text{decoded}}}{B_{\text{total}}}$$
  *(Must use $B_{\text{total}}$ as denominator. Under x86-64, if only 4 instructions out of 93 are decoded, coverage is $\frac{4}{93} \approx 4.3\%$, not $100\%$.)*

---

### Dimension 2: Function Boundary & Symbol Recovery
Evaluates REA's capability to identify function entry points, boundaries, and calling conventions, especially in stripped binaries.

- **Ground-Truth Functions ($F_{\text{GT}}$):** Complete set of functions identified by DWARF debug symbols or Ghidra auto-analysis.
- **Recovered Functions ($F_{\text{REA}}$):** Functions discovered by REA via export tables, ELF symbol tables, call targets, or prologue signatures (`push {r4, lr}`, `push rbp`).
- **Function Entry Precision ($P_{\text{func}}$) & Recall ($R_{\text{func}}$):**
  $$P_{\text{func}} = \frac{|F_{\text{REA}} \cap F_{\text{GT}}|}{|F_{\text{REA}}|}, \quad R_{\text{func}} = \frac{|F_{\text{REA}} \cap F_{\text{GT}}|}{|F_{\text{GT}}|}$$
- **Function Size Concordance:** Mean squared error between ground-truth function byte lengths and REA's recovered function extents.

---

### Dimension 3: Control Flow Graph (CFG) Reconstruction
Evaluates basic block partitioning, terminal branch resolution, and edge accuracy against Radare2 / LLVM CFG models.

- **Basic Block Concordance ($B_{\text{match}}$):** A basic block $[s_{\text{REA}}, e_{\text{REA}}]$ matches ground truth $[s_{\text{GT}}, e_{\text{GT}}]$ if and only if $s_{\text{REA}} = s_{\text{GT}}$ and $e_{\text{REA}} = e_{\text{GT}}$.
- **Edge Precision ($P_{\text{edge}}$) & Recall ($R_{\text{edge}}$):**
  $$P_{\text{edge}} = \frac{|E_{\text{REA}} \cap E_{\text{GT}}|}{|E_{\text{REA}}|}, \quad R_{\text{edge}} = \frac{|E_{\text{REA}} \cap E_{\text{GT}}|}{|E_{\text{GT}}|}$$
- **Indirect Branch Handling:** Tracking how REA classifies computed jumps and calls (`jmp rax`, `bx lr`). REA must explicitly tag unresolved indirect targets as `INCOMPLETE_EDGES` rather than silently dropping edges.

---

### Dimension 4: Reachability Analysis & Soundness Invariants
Evaluates whether REA's reachability engine (`ReachabilityAnalyzer`) correctly determines if a designated code sink is reachable from entry points.

- **Ground-Truth States:** $\{ \text{REACHABLE}, \text{UNREACHABLE} \}$.
- **REA Adjudicated States:** $\{ \text{REACHABLE}, \text{UNREACHABLE}, \text{INCONCLUSIVE} \}$.
- **Soundness Theorem 1 (Unreachable Invariant):**
  $$\text{REA}(\text{Sink}) = \text{UNREACHABLE} \implies \text{CFG}.\text{isComplete} = \text{true} \;\land\; \text{GT}(\text{Sink}) = \text{UNREACHABLE}$$
  *If a CFG is partial, an unreachable claim is invalid and MUST resolve to $\text{INCONCLUSIVE}$.*
- **Soundness Theorem 2 (Reachable Invariant):**
  $$\text{REA}(\text{Sink}) = \text{REACHABLE} \implies \exists \text{ path } \pi \in \text{CFG}: \text{Entry} \rightsquigarrow \text{Sink}$$

---

### Dimension 5: Source-to-Sink Dataflow & Taint Propagation
Evaluates REA's static taint engine (`TaintEngine`) on tracking user-controlled input sources (e.g., `recv`, `read`, `getenv`, `argv`) to dangerous sinks (`strcpy`, `system`, `sprintf`).

- **Taint Recall:** Percentage of genuine dataflow paths reaching a sink that REA tracks.
- **Sanitizer Dominance Detection:** Evaluates whether REA correctly identifies bounds checks, length checks (`strlen`), or sanitizers that dominate the sink and neutralize taint (transitioning finding to `MITIGATED`).
- **Sanitizer Bypass Detection:** Evaluates whether an improper sanitizer (e.g., signed comparison vulnerability, off-by-one check) is correctly rejected as ineffective (preserving taint as `PROVEN_TAINT`).

---

### Dimension 6: Vulnerability Adjudication Precision & Recall
Evaluates the 6-state vulnerability lifecycle engine (`VulnerabilityAdjudicationBridge`).

```
                CONFUSION MATRIX CLASSIFICATION
                ┌───────────────────┬───────────────────┐
                │ Actual Vulnerable │ Actual Clean      │
┌───────────────┼───────────────────┼───────────────────┤
│ REA VERIFIED  │ True Pos (TP)     │ False Pos (FP)    │
├───────────────┼───────────────────┼───────────────────┤
│ REA INCONCL/  │ False Neg (FN)    │ True Neg (TN)     │
│ FALSE_POS     │                   │                   │
└───────────────┴───────────────────┴───────────────────┘
```

- **Precision ($P$):**
  $$P = \frac{\text{TP}}{\text{TP} + \text{FP}}$$
- **Recall ($R$):**
  $$R = \frac{\text{TP}}{\text{TP} + \text{FN}}$$
- **$F_1$-Score:**
  $$F_1 = 2 \cdot \frac{P \cdot R}{P + R}$$
- **Lifecycle Transition Conformance:** Percentage of findings adhering to the formal state transition graph ($0$ illegal transitions permitted).

---

### Dimension 7: Evidence Authenticity, Cryptography & Replay Protection
Evaluates the cryptographic guarantees enforced by `ParentEvidenceValidator` and `TrustedEvidenceAuthority`.

- **Adversarial Tamper Detection Rate:** $100\%$ detection required on mutated payload bytes, mismatched SHA-256 digests, and modified evidence claims.
- **Constant-Time Verification:** Signature checks must execute via `crypto.timingSafeEqual` with zero length-dependent branching.
- **Cold-Restart Witness Replay Protection:** Replaying an already-consumed witness across database restarts must fail closed with `WITNESS_REPLAY_DETECTED` ($100\%$ required).

---

### Dimension 8: Firmware Extraction Correctness
Evaluates `SandboxedExtractor` and `PreWriteValidator` against reference tool extraction (`unsquashfs -ll`).

- **File Count Concordance:** Ratio of extracted files in REA sandbox to total files in reference extraction.
- **Byte Count Concordance:** Ratio of cumulative extracted bytes to reference byte total.
- **Symlink & Path Traversal Immunity:** Zero files written outside sandbox; $100\%$ of malicious traversal attempts (`../../etc/shadow`) intercepted and rejected.

---

### Dimension 9: Resource Consumption & Scalability
Measures runtime efficiency and system resource bounds during analysis.

- **Elapsed Wall-Clock Time ($T_{\text{wall}}$):** Total duration in milliseconds per binary and per firmware image.
- **Peak Process-Family Memory (RSS):** Monitored using Windows Job Object query (`PeakJobMemoryUsed`) and Linux cgroups.
- **CPU Utilization:** User and system CPU time consumed across parent orchestrator and child workers.
- **Disk Footprint:** Peak temporary staging directory size in `C:\Users\acer\AppData\Local\Temp\rea-fw-sandbox-*`.

---

### Dimension 10: Reliability, Crash Containment & Incomplete-Analysis Handling
Evaluates supervisor resilience against worker failure modes.

- **Worker SIGSEGV Containment:** A segmentation fault in a child worker process must not terminate the parent orchestrator; supervisor must settle task cleanly as `FAILED_CLOSED`.
- **Timeout & Stall Recovery:** Workers exceeding deadlines or failing heartbeats must be killed within $1,000\text{ms}$ of deadline expiration.
- **Database Atomicity Under Failure:** Injected persistence errors or stale CAS fencing tokens must result in clean SQLite rollbacks with zero partial state or orphaned finding records.

---

## 3. Evaluation Reporting Standards & Formats

Every completed evaluation run must generate three standardized artifact deliverables in `REA-EVALUATION-LAB/evaluation-reports/`:

1. **Executive Evaluation Summary (`EVAL-<batch_id>-SUMMARY.md`):** High-level scorecard, test pass rates, confusion matrices, and audit recommendations.
2. **Normalized Machine-Readable Metrics (`EVAL-<batch_id>-METRICS.json`):** Full quantitative metric array formatted for automated regression tracking:
   ```json
   {
     "batch_id": "BATCH-L1-20261108",
     "timestamp": 1731057600000,
     "samples_evaluated": 12,
     "metrics": {
       "byte_coverage": {
         "x86_64": 0.043,
         "arm32": 1.0,
         "thumb": 1.0,
         "mips_be": 1.0,
         "mips_le": 1.0
       },
       "vulnerability_detection": {
         "true_positives": 4,
         "false_positives": 0,
         "false_negatives": 1,
         "true_negatives": 7,
         "precision": 1.0,
         "recall": 0.8,
         "f1_score": 0.888
       },
       "resource_averages": {
         "mean_time_ms": 520,
         "peak_rss_mb": 64.2
       }
     }
   }
   ```
3. **Industry Standard SARIF Export (`EVAL-<batch_id>-FINDINGS.sarif`):** SARIF 2.1.0 report linking all verified and candidate findings with complete CWE, CVSS, and rule metadata for external ingestion.


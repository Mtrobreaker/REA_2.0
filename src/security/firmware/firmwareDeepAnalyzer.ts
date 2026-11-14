import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { basename } from "node:path";
import { ok, err, type Result } from "../../domain/result.js";
import type {
  CapecId,
  CweId,
  MitreAttackTechniqueId,
  SecuritySeverityLevel,
} from "../../domain/security/classification.js";
import {
  computeFindingId,
  type FindingLocation,
  type SecurityFinding,
} from "../../domain/security/finding.js";
import type { AssetRecord } from "../../domain/security/asset.js";

export type FirmwareArchitecture =
  | "ARM"
  | "AArch64"
  | "MIPS"
  | "MIPSEL"
  | "RISC-V"
  | "x86"
  | "x86_64"
  | "PowerPC"
  | "UNKNOWN";

export type FilesystemType =
  | "SquashFS"
  | "CramFS"
  | "JFFS2"
  | "UBIFS"
  | "Ext4"
  | "RomFS"
  | "TarGz"
  | "UNKNOWN";

export interface FirmwarePartitionInfo {
  readonly name: string;
  readonly offset: number;
  readonly length: number;
  readonly type: FilesystemType;
  readonly compressed: boolean;
}

export interface FirmwareDeepAnalysisResult {
  readonly target_path: string;
  readonly architecture: FirmwareArchitecture;
  readonly endianness: "little" | "big" | "unknown";
  readonly detected_partitions: readonly FirmwarePartitionInfo[];
  readonly findings: readonly SecurityFinding[];
  readonly risk_score: number; // 0 - 100
  readonly summary: string;
}

export interface FirmwareAnalysisError {
  readonly code: "UNREADABLE_FIRMWARE" | "INVALID_TARGET" | "ANALYSIS_FAILED";
  readonly message: string;
  readonly cause?: unknown;
}

/**
 * Deep Firmware Security Analysis Engine
 * Performs architecture detection, partition identification, credential/secret extraction,
 * bootloader security audit, and insecure configuration analysis.
 */
export class FirmwareDeepAnalyzer {
  public async analyze(
    filePath: string,
    asset?: AssetRecord,
  ): Promise<Result<FirmwareDeepAnalysisResult, FirmwareAnalysisError>> {
    let buffer: Buffer;
    try {
      buffer = await readFile(filePath);
    } catch (e: unknown) {
      return err({
        code: "UNREADABLE_FIRMWARE",
        message: `Failed to read firmware binary at ${filePath}: ${e instanceof Error ? e.message : String(e)}`,
        cause: e,
      });
    }

    const assetRecord: AssetRecord = asset ?? {
      id: `ast_${createHash("sha256").update(filePath).digest("hex")}`,
      name: basename(filePath),
      type: "firmware_image",
      path: filePath,
      digest: { sha256: createHash("sha256").update(buffer).digest("hex") },
      architecture: null,
      version: null,
      environment: null,
      tags: ["firmware-deep-analyzed"],
      metadata: {},
    };

    const archInfo = this.detectArchitecture(buffer);
    const partitions = this.detectPartitions(buffer);
    const findings: SecurityFinding[] = [];

    // 1. Scan for Embedded Private Keys & Certificates
    findings.push(...this.scanPrivateKeys(filePath, buffer, assetRecord));

    // 2. Scan for Embedded Passwords, Hashes & Default IoT Credentials
    findings.push(...this.scanCredentials(filePath, buffer, assetRecord));

    // 3. Scan for Bootloader Security Weaknesses (U-Boot environment)
    findings.push(...this.scanBootloaderSecurity(filePath, buffer, assetRecord));

    // 4. Scan for Insecure Network Services & Cleartext Update Protocols
    findings.push(...this.scanInsecureServices(filePath, buffer, assetRecord));

    // Calculate aggregated risk score (0-100)
    let score = 0;
    for (const f of findings) {
      if (f.severity.level === "CRITICAL") score += 35;
      else if (f.severity.level === "HIGH") score += 20;
      else if (f.severity.level === "MEDIUM") score += 10;
      else if (f.severity.level === "LOW") score += 5;
    }
    const finalScore = Math.min(score, 100);

    const summary =
      `Deep firmware analysis completed for '${assetRecord.name}'. ` +
      `Architecture: ${archInfo.arch} (${archInfo.endianness}-endian). ` +
      `Identified ${partitions.length} partition(s) and ${findings.length} security finding(s) ` +
      `with an aggregate firmware risk score of ${finalScore}/100.`;

    return ok({
      target_path: filePath,
      architecture: archInfo.arch,
      endianness: archInfo.endianness,
      detected_partitions: partitions,
      findings,
      risk_score: finalScore,
      summary,
    });
  }

  // --- Internal Analysis Methods ---

  private detectArchitecture(buffer: Buffer): {
    arch: FirmwareArchitecture;
    endianness: "little" | "big" | "unknown";
  } {
    // 1. Search for ELF header (7F 45 4C 46)
    const elfIndex = buffer.indexOf(Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
    if (elfIndex !== -1 && elfIndex + 20 <= buffer.length) {
      const isLittle = buffer[elfIndex + 5] === 1;
      const machine = isLittle
        ? buffer.readUInt16LE(elfIndex + 18)
        : buffer.readUInt16BE(elfIndex + 18);

      const endianness = isLittle ? "little" : "big";
      switch (machine) {
        case 0x28: // ARM
          return { arch: "ARM", endianness };
        case 0xb7: // AArch64
          return { arch: "AArch64", endianness };
        case 0x08: // MIPS
          return { arch: isLittle ? "MIPSEL" : "MIPS", endianness };
        case 0xf3: // RISC-V
          return { arch: "RISC-V", endianness };
        case 0x03: // x86
          return { arch: "x86", endianness };
        case 0x3e: // x86_64
          return { arch: "x86_64", endianness };
        case 0x14: // PowerPC
          return { arch: "PowerPC", endianness };
      }
    }

    // 2. String heuristics
    const latin = buffer.toString("latin1");
    if (latin.includes("ARMv7") || latin.includes("Cortex-A") || latin.includes("cortex-m")) {
      return { arch: "ARM", endianness: "little" };
    }
    if (latin.includes("mips_") || latin.includes("mips32")) {
      return { arch: "MIPS", endianness: "little" };
    }
    if (latin.includes("riscv32") || latin.includes("riscv64")) {
      return { arch: "RISC-V", endianness: "little" };
    }

    return { arch: "UNKNOWN", endianness: "unknown" };
  }

  private detectPartitions(buffer: Buffer): FirmwarePartitionInfo[] {
    const partitions: FirmwarePartitionInfo[] = [];

    // SquashFS magic 'hsqs' (0x73717368) or 'sqsh' (0x68737173)
    const hsqs = Buffer.from([0x68, 0x73, 0x71, 0x73]);
    const sqsh = Buffer.from([0x73, 0x71, 0x73, 0x68]);
    let offset = 0;
    while ((offset = buffer.indexOf(hsqs, offset)) !== -1) {
      partitions.push({
        name: `squashfs_${partitions.length + 1}`,
        offset,
        length: 0,
        type: "SquashFS",
        compressed: true,
      });
      offset += 4;
    }
    offset = 0;
    while ((offset = buffer.indexOf(sqsh, offset)) !== -1) {
      partitions.push({
        name: `squashfs_be_${partitions.length + 1}`,
        offset,
        length: 0,
        type: "SquashFS",
        compressed: true,
      });
      offset += 4;
    }

    // JFFS2 magic 0x1985
    const jffs2 = Buffer.from([0x19, 0x85]);
    const jffsOffset = buffer.indexOf(jffs2);
    if (jffsOffset !== -1) {
      partitions.push({
        name: "jffs2_rootfs",
        offset: jffsOffset,
        length: 0,
        type: "JFFS2",
        compressed: true,
      });
    }

    // U-Boot legacy image magic (0x27051956)
    const uimage = Buffer.from([0x27, 0x05, 0x19, 0x56]);
    const uimageOffset = buffer.indexOf(uimage);
    if (uimageOffset !== -1) {
      partitions.push({
        name: "uimage_kernel",
        offset: uimageOffset,
        length: 0,
        type: "UNKNOWN",
        compressed: true,
      });
    }

    return partitions;
  }

  private scanPrivateKeys(
    filePath: string,
    buffer: Buffer,
    asset: AssetRecord,
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const content = buffer.toString("latin1");

    const keyPatterns = [
      { tag: "RSA PRIVATE KEY", type: "RSA" },
      { tag: "OPENSSH PRIVATE KEY", type: "OpenSSH" },
      { tag: "EC PRIVATE KEY", type: "Elliptic Curve" },
      { tag: "ENCRYPTED PRIVATE KEY", type: "PKCS#8" },
    ];

    for (const kp of keyPatterns) {
      const header = `-----BEGIN ${kp.tag}-----`;
      const idx = content.indexOf(header);
      if (idx !== -1) {
        const rootCause = `Unencrypted cryptographic ${kp.type} private key was packaged into distributed firmware image.`;
        const location: FindingLocation = {
          file: filePath,
          function: null,
          line: null,
          column: null,
          end_line: null,
          module: "EmbeddedSecrets",
          component: "cryptography",
          address: null,
          offset: idx,
        };

        const findingId = computeFindingId({
          asset_id: asset.id,
          name: `Embedded Cryptographic ${kp.type} Private Key`,
          location,
          root_cause: rootCause,
        });

        findings.push({
          id: findingId,
          name: `Embedded Cryptographic ${kp.type} Private Key`,
          affected_asset: {
            id: asset.id,
            name: asset.name,
            type: asset.type,
          },
          location,
          technical_description: `The firmware image contains a ${kp.type} private key embedded at byte offset 0x${idx.toString(16)}. Attackers extracting this key can impersonate the device, forge telemetry, or compromise encrypted TLS communications.`,
          root_cause: rootCause,
          evidence_ids: [],
          reproduction_steps: [
            `Extract string matches: strings -t x ${filePath} | grep "BEGIN ${kp.tag}"`,
          ],
          impact: {
            description: "Breakdown of device cryptographic trust boundary and authentication.",
            attack_prerequisites: ["Firmware image acquisition"],
            exploitability: "THEORETICAL",
          },
          severity: {
            level: "CRITICAL",
            cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            cvss_score: 7.7,
            justification: "Extraction of private keys compromises mutual TLS and device authenticity.",
          },
          confidence: {
            level: "CONFIRMED",
            false_positive_considerations: ["Mock or test keys in staging builds"],
            verification_method: "Exact PEM header signature match",
          },
          remediation: {
            description: "Remove embedded private keys. Provision unique per-device keys into an on-chip Secure Element (e.g. ATECC608, TPM 2.0) at manufacturing.",
            code_diff: null,
            config_example: null,
            priority: "IMMEDIATE",
            validation_procedure: `Ensure firmware image build output has zero instances of 'BEGIN ${kp.tag}'.`,
          },
          classification: {
            cve: [],
            cwe: ["CWE-798" as CweId],
            capec: ["CAPEC-37" as CapecId],
            mitre_attack: ["T1552" as MitreAttackTechniqueId],
            owasp: ["A07:2021-Identification and Authentication Failures"],
          },
          verification_status: "CANDIDATE",
          provenance: {
            discovered_by: "firmware-deep-analyzer",
            discovered_at: new Date().toISOString(),
            verified_by: null,
            verified_at: null,
          },
        });
      }
    }

    return findings;
  }

  private scanCredentials(
    filePath: string,
    buffer: Buffer,
    asset: AssetRecord,
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const content = buffer.toString("latin1");

    // Check for hardcoded shadow hash entries: root:$1$ (MD5) or root:$6$ (SHA-512)
    const shadowMatch = content.match(/root:(\$[156]\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+):/);
    if (shadowMatch && shadowMatch.index !== undefined) {
      const hashStr = shadowMatch[1]!;
      const isWeakMd5 = hashStr.startsWith("$1$");
      const rootCause = "Hardcoded static password hash in firmware filesystem shadow file.";

      const location: FindingLocation = {
        file: filePath,
        function: null,
        line: null,
        column: null,
        end_line: null,
        module: "etc/shadow",
        component: "authentication",
        address: null,
        offset: shadowMatch.index,
      };

      const findingId = computeFindingId({
        asset_id: asset.id,
        name: "Hardcoded Root Password Hash in Firmware",
        location,
        root_cause: rootCause,
      });

      findings.push({
        id: findingId,
        name: "Hardcoded Root Password Hash in Firmware",
        affected_asset: {
          id: asset.id,
          name: asset.name,
          type: asset.type,
        },
        location,
        technical_description: `Firmware contains an embedded root password hash in shadow format (${isWeakMd5 ? "Weak MD5 crypt" : "SHA-512 crypt"}) at offset 0x${shadowMatch.index.toString(16)}. Attackers can perform offline cracking to obtain the administrative root password.`,
        root_cause: rootCause,
        evidence_ids: [],
        reproduction_steps: [
          `Inspect offset 0x${shadowMatch.index.toString(16)} for shadow string: ${shadowMatch[0]}`,
        ],
        impact: {
          description: "Administrative access across all devices sharing the same firmware image.",
          attack_prerequisites: ["Local console, SSH, or telnet interface access"],
          exploitability: "THEORETICAL",
        },
        severity: {
          level: isWeakMd5 ? "CRITICAL" : "HIGH",
          cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          cvss_score: isWeakMd5 ? 9.8 : 8.8,
          justification: "Static credentials allow universal device takeover.",
        },
        confidence: {
          level: "CONFIRMED",
          false_positive_considerations: [],
          verification_method: "Shadow entry format regex match",
        },
        remediation: {
          description: "Disable static root passwords. Force user-defined password on first boot, or enforce SSH key-based authentication only.",
          code_diff: null,
          config_example: "root:*:19000:0:99999:7:::",
          priority: "IMMEDIATE",
          validation_procedure: "Verify /etc/shadow in target rootfs locks root account with '*'.",
        },
        classification: {
          cve: [],
          cwe: ["CWE-259" as CweId],
          capec: ["CAPEC-16" as CapecId],
          mitre_attack: ["T1078" as MitreAttackTechniqueId],
          owasp: ["A07:2021-Identification and Authentication Failures"],
        },
        verification_status: "CANDIDATE",
        provenance: {
          discovered_by: "firmware-deep-analyzer",
          discovered_at: new Date().toISOString(),
          verified_by: null,
          verified_at: null,
        },
      });
    }

    return findings;
  }

  private scanBootloaderSecurity(
    filePath: string,
    buffer: Buffer,
    asset: AssetRecord,
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const content = buffer.toString("latin1");

    // Check for insecure bootargs giving root shell without auth (init=/bin/sh or console=ttyS0 without login)
    if (content.includes("init=/bin/sh") || content.includes("init=/bin/bash")) {
      const idx = content.indexOf("init=/bin/sh");
      const rootCause = "Bootloader boot arguments explicitly bypass authentication by spawning /bin/sh as init process.";

      const location: FindingLocation = {
        file: filePath,
        function: null,
        line: null,
        column: null,
        end_line: null,
        module: "Bootloader",
        component: "U-Boot_Environment",
        address: null,
        offset: idx !== -1 ? idx : 0,
      };

      const findingId = computeFindingId({
        asset_id: asset.id,
        name: "Insecure Bootloader Arguments (Init Shell Bypass)",
        location,
        root_cause: rootCause,
      });

      findings.push({
        id: findingId,
        name: "Insecure Bootloader Arguments (Init Shell Bypass)",
        affected_asset: {
          id: asset.id,
          name: asset.name,
          type: asset.type,
        },
        location,
        technical_description: "The bootloader configuration or default kernel bootargs contains 'init=/bin/sh', which bypasses standard init initialization and login authenticators, dropping directly into a root shell.",
        root_cause: rootCause,
        evidence_ids: [],
        reproduction_steps: [`Inspect boot parameters in firmware binary: grep -a "init=/bin/sh"`],
        impact: {
          description: "Unauthenticated root shell via serial/UART console during boot.",
          attack_prerequisites: ["Physical access to UART or boot console"],
          exploitability: "THEORETICAL",
        },
        severity: {
          level: "HIGH",
          cvss_vector: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          cvss_score: 6.8,
          justification: "Physical access grants immediate root access without credentials.",
        },
        confidence: {
          level: "CONFIRMED",
          false_positive_considerations: ["Development engineering builds"],
          verification_method: "Exact string match in bootargs partition",
        },
        remediation: {
          description: "Remove 'init=/bin/sh' from bootargs. Ensure init points to standard '/sbin/init' or systemd with active authentication.",
          code_diff: null,
          config_example: "bootargs=console=ttyS0,115200 root=/dev/mtdblock2 rootfstype=squashfs ro",
          priority: "SHORT_TERM",
          validation_procedure: "Verify U-Boot environment variables contain no init shell bypass.",
        },
        classification: {
          cve: [],
          cwe: ["CWE-288" as CweId],
          capec: ["CAPEC-115" as CapecId],
          mitre_attack: ["T1542" as MitreAttackTechniqueId],
          owasp: [],
        },
        verification_status: "CANDIDATE",
        provenance: {
          discovered_by: "firmware-deep-analyzer",
          discovered_at: new Date().toISOString(),
          verified_by: null,
          verified_at: null,
        },
      });
    }

    return findings;
  }

  private scanInsecureServices(
    filePath: string,
    buffer: Buffer,
    asset: AssetRecord,
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const content = buffer.toString("latin1");

    // Check for telnetd daemon startup script
    if (content.includes("/usr/sbin/telnetd") || content.includes("telnetd -l /bin/sh")) {
      const idx = content.indexOf("telnetd");
      const rootCause = "Cleartext, unencrypted telnet daemon configured to execute on startup.";

      const location: FindingLocation = {
        file: filePath,
        function: null,
        line: null,
        column: null,
        end_line: null,
        module: "etc/init.d",
        component: "network_services",
        address: null,
        offset: idx !== -1 ? idx : 0,
      };

      const findingId = computeFindingId({
        asset_id: asset.id,
        name: "Unencrypted Telnet Daemon Enabled in Firmware",
        location,
        root_cause: rootCause,
      });

      findings.push({
        id: findingId,
        name: "Unencrypted Telnet Daemon Enabled in Firmware",
        affected_asset: {
          id: asset.id,
          name: asset.name,
          type: asset.type,
        },
        location,
        technical_description: "The firmware startup scripts invoke telnetd, exposing an unencrypted cleartext management daemon over port 23, exposing credentials to network interception.",
        root_cause: rootCause,
        evidence_ids: [],
        reproduction_steps: [`Search startup scripts for telnetd: grep -a "telnetd"`],
        impact: {
          description: "Credential eavesdropping and unauthorized remote access.",
          attack_prerequisites: ["Network adjacency to device"],
          exploitability: "THEORETICAL",
        },
        severity: {
          level: "HIGH",
          cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
          cvss_score: 7.5,
          justification: "Cleartext transport of authentication credentials.",
        },
        confidence: {
          level: "CONFIRMED",
          false_positive_considerations: [],
          verification_method: "Init script daemon invocation match",
        },
        remediation: {
          description: "Disable telnetd. Replace with SSH (Dropbear or OpenSSH) using certificate or key-based authentication.",
          code_diff: null,
          config_example: "# /usr/sbin/telnetd\n/usr/sbin/dropbear -s -p 22",
          priority: "SHORT_TERM",
          validation_procedure: "Port scan device to confirm port 23 is closed.",
        },
        classification: {
          cve: [],
          cwe: ["CWE-319" as CweId],
          capec: ["CAPEC-94" as CapecId],
          mitre_attack: ["T1040" as MitreAttackTechniqueId],
          owasp: ["A02:2021-Cryptographic Failures"],
        },
        verification_status: "CANDIDATE",
        provenance: {
          discovered_by: "firmware-deep-analyzer",
          discovered_at: new Date().toISOString(),
          verified_by: null,
          verified_at: null,
        },
      });
    }

    return findings;
  }
}

export const defaultFirmwareDeepAnalyzer = new FirmwareDeepAnalyzer();


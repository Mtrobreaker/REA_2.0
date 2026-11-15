import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { ok, type Result } from "../../domain/result.js";
import {
  computeFindingId,
  type FindingLocation,
  type SecurityFinding,
} from "../../domain/security/finding.js";
import type { AssetId, AssetRecord } from "../../domain/security/asset.js";
import type {
  CweId,
  SecuritySeverityLevel,
} from "../../domain/security/classification.js";

export interface EmbeddedOsAnalysisResult {
  readonly root_path: string;
  readonly findings: readonly SecurityFinding[];
  readonly scanned_components: readonly string[];
  readonly accounts: readonly {
    username: string;
    uid: number;
    has_password: boolean;
    hash_algorithm: string;
  }[];
}

export class EmbeddedOsAnalyzer {
  public async analyze(
    rootPath: string,
    asset?: AssetRecord,
  ): Promise<Result<EmbeddedOsAnalysisResult, Error>> {
    const findings: SecurityFinding[] = [];
    const scannedComponents: string[] = [];
    const accounts: {
      username: string;
      uid: number;
      has_password: boolean;
      hash_algorithm: string;
    }[] = [];

    const defaultAsset: AssetRecord = asset ?? {
      id: "ast_0000000000000000000000000000000000000000000000000000000000000000" as AssetId,
      name: "Target Operating System",
      type: "operating_system",
      path: rootPath,
      digest: null,
      architecture: null,
      version: null,
      environment: null,
      tags: [],
      metadata: {},
    };

    const makeFinding = (opts: {
      name: string;
      severity: SecuritySeverityLevel;
      cvssVector: string;
      cvssScore: number;
      cweId: CweId;
      filePath: string;
      line: number;
      technicalDescription: string;
      rootCause: string;
      remediationDesc: string;
    }): SecurityFinding => {
      const location: FindingLocation = {
        file: opts.filePath,
        function: null,
        line: opts.line,
        column: null,
        end_line: null,
        module: "os/config",
        component: "operating_system",
        address: null,
        offset: null,
      };

      const id = computeFindingId({
        asset_id: defaultAsset.id,
        name: opts.name,
        location,
        root_cause: opts.rootCause,
      });

      return {
        id,
        name: opts.name,
        affected_asset: {
          id: defaultAsset.id,
          name: defaultAsset.name,
          type: defaultAsset.type,
        },
        location,
        technical_description: opts.technicalDescription,
        root_cause: opts.rootCause,
        evidence_ids: [],
        reproduction_steps: [`Inspect line ${opts.line} in ${opts.filePath}`],
        impact: {
          description: "Elevated privileges or unauthorized device access.",
          attack_prerequisites: ["Local or network access to device"],
          exploitability: "THEORETICAL",
        },
        severity: {
          level: opts.severity,
          cvss_vector: opts.cvssVector,
          cvss_score: opts.cvssScore,
          justification: opts.technicalDescription,
        },
        confidence: {
          level: "CONFIRMED",
          false_positive_considerations: [],
          verification_method: "Static OS configuration parse",
        },
        remediation: {
          description: opts.remediationDesc,
          code_diff: null,
          config_example: null,
          priority: opts.severity === "CRITICAL" ? "IMMEDIATE" : "SHORT_TERM",
          validation_procedure: `Verify ${opts.filePath} does not contain the offending configuration.`,
        },
        classification: {
          cve: [],
          cwe: [opts.cweId],
          capec: [],
          mitre_attack: [],
          owasp: [],
        },
        verification_status: "CANDIDATE",
        provenance: {
          discovered_by: "embedded-os-analyzer",
          discovered_at: new Date().toISOString(),
          verified_by: null,
          verified_at: null,
        },
      };
    };

    // 1. Audit /etc/passwd and /etc/shadow
    const etcDir = join(rootPath, "etc");
    if (existsSync(etcDir)) {
      scannedComponents.push("/etc");
      const passwdPath = join(etcDir, "passwd");
      const shadowPath = join(etcDir, "shadow");
      const uidMap = new Map<string, number>();

      if (existsSync(passwdPath)) {
        const passwdContent = readFileSync(passwdPath, "utf-8");
        const lines = passwdContent.split("\n");
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i]?.trim();
          if (!line || line.startsWith("#")) continue;
          const parts = line.split(":");
          if (parts.length >= 3) {
            const username = parts[0] ?? "";
            const uid = parseInt(parts[2] ?? "1000", 10);
            uidMap.set(username, uid);

            if (uid === 0 && username !== "root") {
              findings.push(
                makeFinding({
                  name: `Backdoor UID 0 Superuser Account: ${username}`,
                  severity: "CRITICAL",
                  cvssVector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                  cvssScore: 8.4,
                  cweId: "CWE-250" as CweId,
                  filePath: passwdPath,
                  line: i + 1,
                  technicalDescription: `User '${username}' has UID 0 granting unrestricted superuser privileges.`,
                  rootCause:
                    "Hardcoded secondary superuser account in /etc/passwd.",
                  remediationDesc: `Remove user '${username}' or assign a non-zero UID.`,
                }),
              );
            }
          }
        }
      }

      const passwordSourcePath = existsSync(shadowPath)
        ? shadowPath
        : passwdPath;
      if (existsSync(passwordSourcePath)) {
        const content = readFileSync(passwordSourcePath, "utf-8");
        const lines = content.split("\n");
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i]?.trim();
          if (!line || line.startsWith("#")) continue;
          const parts = line.split(":");
          if (parts.length >= 2) {
            const username = parts[0] ?? "";
            const hash = parts[1] ?? "";
            const uid = uidMap.get(username) ?? 1000;

            let hashType = "none";
            let isWeak = false;

            if (hash === "" || hash === "!") {
              hashType = hash === "" ? "blank" : "disabled";
            } else if (hash.startsWith("$1$")) {
              hashType = "MD5";
              isWeak = true;
            } else if (hash.startsWith("$2a$") || hash.startsWith("$2y$")) {
              hashType = "Blowfish";
            } else if (hash.startsWith("$5$")) {
              hashType = "SHA-256";
            } else if (hash.startsWith("$6$")) {
              hashType = "SHA-512";
            } else if (hash.length === 13 && !hash.startsWith("$")) {
              hashType = "DES";
              isWeak = true;
            }

            accounts.push({
              username,
              uid,
              has_password: hash !== "" && hash !== "!",
              hash_algorithm: hashType,
            });

            if (hash === "" && (uid === 0 || username === "admin")) {
              findings.push(
                makeFinding({
                  name: `Blank Password on Privileged Account: ${username}`,
                  severity: "CRITICAL",
                  cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                  cvssScore: 9.8,
                  cweId: "CWE-258" as CweId,
                  filePath: passwordSourcePath,
                  line: i + 1,
                  technicalDescription: `Privileged user '${username}' has a blank password hash allowing unauthenticated access.`,
                  rootCause: "Empty password field in credentials database.",
                  remediationDesc: `Enforce a strong password hash for user '${username}'.`,
                }),
              );
            }

            if (isWeak) {
              findings.push(
                makeFinding({
                  name: `Cryptographically Weak Password Hash (${hashType}) for ${username}`,
                  severity: "HIGH",
                  cvssVector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                  cvssScore: 6.2,
                  cweId: "CWE-327" as CweId,
                  filePath: passwordSourcePath,
                  line: i + 1,
                  technicalDescription: `User '${username}' uses a legacy ${hashType} password hash prone to rapid cracking.`,
                  rootCause: `Outdated password hashing algorithm (${hashType}).`,
                  remediationDesc: "Upgrade to SHA-512 ($6$) or Yescrypt.",
                }),
              );
            }
          }
        }
      }
    }

    // 2. Audit Kernel Configuration
    const kernelConfigFiles = ["config.gz", "config", ".config"];
    for (const cfg of kernelConfigFiles) {
      const p = join(rootPath, "boot", cfg);
      const rootP = join(rootPath, cfg);
      const targetP = existsSync(p) ? p : existsSync(rootP) ? rootP : null;

      if (targetP) {
        scannedComponents.push(targetP);
        try {
          const configContent = readFileSync(targetP, "utf-8");
          if (!configContent.includes("CONFIG_RANDOMIZE_BASE=y")) {
            findings.push(
              makeFinding({
                name: "Linux Kernel Missing KASLR (CONFIG_RANDOMIZE_BASE)",
                severity: "MEDIUM",
                cvssVector: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
                cvssScore: 7.0,
                cweId: "CWE-693" as CweId,
                filePath: targetP,
                line: 1,
                technicalDescription:
                  "Kernel built without KASLR facilitates return-oriented programming (ROP) exploits.",
                rootCause: "CONFIG_RANDOMIZE_BASE is not enabled.",
                remediationDesc:
                  "Enable CONFIG_RANDOMIZE_BASE=y in kernel compilation configuration.",
              }),
            );
          }

          if (!configContent.includes("CONFIG_STACKPROTECTOR_STRONG=y")) {
            findings.push(
              makeFinding({
                name: "Linux Kernel Missing Stack Protector Strong",
                severity: "MEDIUM",
                cvssVector: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
                cvssScore: 7.0,
                cweId: "CWE-119" as CweId,
                filePath: targetP,
                line: 1,
                technicalDescription:
                  "Kernel functions lack stack protector strong bounds checking.",
                rootCause: "CONFIG_STACKPROTECTOR_STRONG is not set.",
                remediationDesc:
                  "Enable CONFIG_STACKPROTECTOR_STRONG=y in kernel compilation configuration.",
              }),
            );
          }
        } catch {
          // Ignored
        }
      }
    }

    return ok({
      root_path: rootPath,
      findings,
      scanned_components: scannedComponents,
      accounts,
    });
  }
}

export const defaultEmbeddedOsAnalyzer = new EmbeddedOsAnalyzer();

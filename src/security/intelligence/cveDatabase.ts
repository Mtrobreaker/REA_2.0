import { err, ok, type Result } from "../../domain/result.js";
import {
  isCveId,
  type CveId,
  type CweId,
  type SecuritySeverityLevel,
} from "../../domain/security/classification.js";
import {
  calculateCvss31FromVector,
  type Cvss31CalculationResult,
} from "../../domain/security/cvssCalculator.js";
import type { SecurityFinding } from "../../domain/security/finding.js";

export interface CveRecord {
  readonly id: CveId;
  readonly title: string;
  readonly description: string;
  readonly cwe_ids: readonly CweId[];
  readonly cvss_v31_vector: string;
  readonly references: readonly string[];
  readonly affected_components: readonly string[];
  readonly published_at: string;
}

export interface CveEnrichment {
  readonly cve: CveRecord;
  readonly cvss: Cvss31CalculationResult;
}

/**
 * Embedded offline benchmark database of landmark high-impact CVEs.
 * Guarantees instant, air-gapped threat intelligence without external network dependencies.
 */
const EMBEDDED_CVE_DATABASE: readonly CveRecord[] = [
  {
    id: "CVE-2021-44228" as CveId,
    title: "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
    description:
      "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
    cwe_ids: ["CWE-502" as CweId, "CWE-400" as CweId],
    cvss_v31_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    references: [
      "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
      "https://logging.apache.org/log4j/2.x/security.html",
    ],
    affected_components: ["org.apache.logging.log4j:log4j-core"],
    published_at: "2021-12-10T10:15:00.000Z",
  },
  {
    id: "CVE-2014-0160" as CveId,
    title: "OpenSSL TLS Heartbeat Information Disclosure (Heartbleed)",
    description:
      "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, allowing remote attackers to obtain sensitive information from process memory.",
    cwe_ids: ["CWE-125" as CweId, "CWE-119" as CweId],
    cvss_v31_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    references: ["https://heartbleed.com/", "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"],
    affected_components: ["openssl"],
    published_at: "2014-04-07T00:00:00.000Z",
  },
  {
    id: "CVE-2017-0144" as CveId,
    title: "Microsoft Windows SMBv1 Remote Code Execution (EternalBlue)",
    description:
      "The SMBv1 server in Microsoft Windows allows remote attackers to execute arbitrary code via crafted packets, as exploited in the WannaCry ransomware outbreak.",
    cwe_ids: ["CWE-119" as CweId],
    cvss_v31_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    references: ["https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010"],
    affected_components: ["srv.sys", "smbv1"],
    published_at: "2017-03-14T00:00:00.000Z",
  },
  {
    id: "CVE-2023-44487" as CveId,
    title: "HTTP/2 Rapid Reset Denial of Service",
    description:
      "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, exhausting server resources.",
    cwe_ids: ["CWE-400" as CweId],
    cvss_v31_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
    affected_components: ["http2", "nghttp2", "envoy", "nginx"],
    published_at: "2023-10-10T12:00:00.000Z",
  },
  {
    id: "CVE-2022-22965" as CveId,
    title: "Spring Framework Remote Code Execution (Spring4Shell)",
    description:
      "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution via data binding when using a non-standard ClassLoader.",
    cwe_ids: ["CWE-94" as CweId],
    cvss_v31_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    references: ["https://spring.io/security/cve-2022-22965"],
    affected_components: ["org.springframework:spring-beans"],
    published_at: "2022-04-01T00:00:00.000Z",
  },
  {
    id: "CVE-2021-26855" as CveId,
    title: "Microsoft Exchange Server SSRF (ProxyLogon)",
    description:
      "Microsoft Exchange Server Remote Code Execution Vulnerability via pre-authentication SSRF in the frontend HTTP proxy.",
    cwe_ids: ["CWE-918" as CweId],
    cvss_v31_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    references: ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855"],
    affected_components: ["microsoft:exchange_server"],
    published_at: "2021-03-02T00:00:00.000Z",
  },
];

/**
 * In-memory and offline CVE Threat Intelligence database.
 */
export class CveDatabase {
  private readonly records = new Map<string, CveRecord>();

  constructor(customRecords: readonly CveRecord[] = []) {
    // Populate with offline embedded records
    for (const rec of EMBEDDED_CVE_DATABASE) {
      this.records.set(rec.id, rec);
    }
    // Populate custom records
    for (const rec of customRecords) {
      this.records.set(rec.id, rec);
    }
  }

  public register(record: CveRecord): void {
    this.records.set(record.id, record);
  }

  public lookup(cveId: string): Result<CveEnrichment, { message: string }> {
    if (!isCveId(cveId)) {
      return err({ message: `Invalid CVE format: '${cveId}'` });
    }

    const record = this.records.get(cveId);
    if (!record) {
      return err({ message: `CVE '${cveId}' not found in local database.` });
    }

    const cvss = calculateCvss31FromVector(record.cvss_v31_vector);
    if (!cvss.ok) {
      return err({
        message: `Failed to compute CVSS for ${cveId}: ${cvss.error.message}`,
      });
    }

    return ok({
      cve: record,
      cvss: cvss.value,
    });
  }

  public queryByCwe(cweId: string): CveRecord[] {
    return Array.from(this.records.values()).filter((r) =>
      r.cwe_ids.some((cwe) => cwe === cweId),
    );
  }

  public get size(): number {
    return this.records.size;
  }

  /**
   * Enrich a SecurityFinding with official CVE metadata and calculated CVSS score.
   */
  public enrichFinding(finding: SecurityFinding): SecurityFinding {
    if (finding.classification.cve.length === 0) {
      return finding;
    }

    const firstCve = finding.classification.cve[0];
    if (!firstCve) return finding;

    const enrichment = this.lookup(firstCve);
    if (!enrichment.ok) {
      return finding;
    }

    const { cve, cvss } = enrichment.value;

    const mergedCwes = Array.from(
      new Set([...finding.classification.cwe, ...cve.cwe_ids]),
    );

    return {
      ...finding,
      technical_description:
        finding.technical_description.length > cve.description.length
          ? finding.technical_description
          : cve.description,
      severity: {
        level: cvss.severity as SecuritySeverityLevel,
        cvss_vector: cvss.vector_string,
        cvss_score: cvss.score,
        justification: `Enriched from official CVE entry for ${cve.id}`,
      },
      classification: {
        ...finding.classification,
        cwe: mergedCwes,
      },
    };
  }
}

/** Default singleton instance of the CVE database */
export const defaultCveDatabase = new CveDatabase();

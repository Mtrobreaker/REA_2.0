import { createHash } from "node:crypto";
import type { AssessmentState } from "../../domain/security/assessment.js";
import type { AssetRecord } from "../../domain/security/asset.js";
import type { SecuritySeverityLevel } from "../../domain/security/classification.js";
import type { SecurityFinding } from "../../domain/security/finding.js";

export type NodeType =
  | "asset"
  | "finding"
  | "cve"
  | "cwe"
  | "mitre_technique"
  | "capec";

export type EdgeRelationship =
  | "AFFECTS"
  | "CLASSIFIED_AS_CWE"
  | "CORRELATED_WITH_CVE"
  | "LEVERAGES_TECHNIQUE"
  | "EXPLOITS_CAPEC"
  | "CHAINED_TO"
  | "CONNECTS_TO_ASSET";

export interface GraphNode {
  readonly id: string;
  readonly type: NodeType;
  readonly label: string;
  readonly severity?: SecuritySeverityLevel;
  readonly cvss_score?: number | null;
  readonly metadata: Readonly<Record<string, unknown>>;
}

export interface GraphEdge {
  readonly id: string;
  readonly source: string;
  readonly target: string;
  readonly relationship: EdgeRelationship;
  readonly weight: number;
}

export interface AttackPathStep {
  readonly fromNode: GraphNode;
  readonly toNode: GraphNode;
  readonly edge: GraphEdge;
  readonly explanation: string;
}

export interface AttackPath {
  readonly path_id: string;
  readonly title: string;
  readonly steps: readonly AttackPathStep[];
  readonly cumulative_risk: number;
  readonly overall_severity: SecuritySeverityLevel;
  readonly narrative: string;
}

export interface CrownJewelRiskReport {
  readonly crown_jewel_assets: readonly AssetRecord[];
  readonly reachable_paths: readonly AttackPath[];
  readonly highest_path_risk: number;
  readonly posture_verdict: "COMPROMISED" | "HIGH_RISK" | "ELEVATED" | "RESILIENT";
}

/**
 * Security Knowledge Graph & Multi-Hop Attack Path Modeling Engine
 * Constructs a typed heterogeneous property graph connecting assets, vulnerabilities,
 * CVEs, CWEs, and MITRE ATT&CK techniques, and calculates feasible exploit chains.
 */
export class SecurityKnowledgeGraph {
  private readonly nodesMap = new Map<string, GraphNode>();
  private readonly edgesList: GraphEdge[] = [];
  private readonly adjacencyMap = new Map<string, GraphEdge[]>();

  constructor(assessment?: AssessmentState) {
    if (assessment) {
      this.populateFromAssessment(assessment);
    }
  }

  public get nodes(): readonly GraphNode[] {
    return Array.from(this.nodesMap.values());
  }

  public get edges(): readonly GraphEdge[] {
    return [...this.edgesList];
  }

  public getNode(id: string): GraphNode | undefined {
    return this.nodesMap.get(id);
  }

  public addNode(node: GraphNode): void {
    this.nodesMap.set(node.id, node);
    if (!this.adjacencyMap.has(node.id)) {
      this.adjacencyMap.set(node.id, []);
    }
  }

  public addEdge(
    source: string,
    target: string,
    relationship: EdgeRelationship,
    weight = 1.0,
  ): void {
    const edgeId = `edge_${createHash("sha256")
      .update(`${source}:${relationship}:${target}`)
      .digest("hex")
      .slice(0, 16)}`;

    const edge: GraphEdge = {
      id: edgeId,
      source,
      target,
      relationship,
      weight,
    };

    this.edgesList.push(edge);

    const adj = this.adjacencyMap.get(source) ?? [];
    adj.push(edge);
    this.adjacencyMap.set(source, adj);
  }

  /**
   * Build complete graph from an assessment state.
   */
  public populateFromAssessment(assessment: AssessmentState): void {
    // 1. Add Asset Nodes
    for (const asset of assessment.assets) {
      this.addNode({
        id: asset.id,
        type: "asset",
        label: asset.name,
        metadata: {
          asset_type: asset.type,
          path: asset.path,
          tags: asset.tags,
          is_crown_jewel:
            asset.tags.includes("critical") ||
            asset.tags.includes("backend") ||
            Boolean(asset.metadata.crown_jewel),
        },
      });
    }

    // Connect assets that share common namespaces or dependencies
    for (let i = 0; i < assessment.assets.length; i++) {
      for (let j = 0; j < assessment.assets.length; j++) {
        if (i !== j) {
          const a = assessment.assets[i]!;
          const b = assessment.assets[j]!;
          // Firmware image connecting to compiled binary or RTL
          if (
            (a.type === "firmware_image" && b.type === "compiled_binary") ||
            (a.type === "source_repository" && b.type === "compiled_binary") ||
            (a.type === "firmware_image" && b.type === "source_repository")
          ) {
            this.addEdge(a.id, b.id, "CONNECTS_TO_ASSET", 0.5);
          }
        }
      }
    }

    // 2. Add Finding Nodes & Relationships
    for (const f of assessment.findings) {
      this.addNode({
        id: f.id,
        type: "finding",
        label: f.name,
        severity: f.severity.level,
        cvss_score: f.severity.cvss_score,
        metadata: {
          verification_status: f.verification_status,
          root_cause: f.root_cause,
          impact: f.impact.description,
          remediation_priority: f.remediation.priority,
        },
      });

      // Edge: Finding -> Asset
      this.addEdge(f.id, f.affected_asset.id, "AFFECTS", 1.0);

      // Edge: Finding -> CWE
      for (const cwe of f.classification.cwe) {
        if (!this.nodesMap.has(cwe)) {
          this.addNode({
            id: cwe,
            type: "cwe",
            label: cwe,
            metadata: {},
          });
        }
        this.addEdge(f.id, cwe, "CLASSIFIED_AS_CWE", 0.2);
      }

      // Edge: Finding -> CVE
      for (const cve of f.classification.cve) {
        if (!this.nodesMap.has(cve)) {
          this.addNode({
            id: cve,
            type: "cve",
            label: cve,
            metadata: {},
          });
        }
        this.addEdge(f.id, cve, "CORRELATED_WITH_CVE", 0.2);
      }

      // Edge: Finding -> MITRE ATT&CK
      for (const tech of f.classification.mitre_attack) {
        if (!this.nodesMap.has(tech)) {
          this.addNode({
            id: tech,
            type: "mitre_technique",
            label: tech,
            metadata: {},
          });
        }
        this.addEdge(f.id, tech, "LEVERAGES_TECHNIQUE", 0.3);
      }

      // Edge: Finding -> CAPEC
      for (const capec of f.classification.capec) {
        if (!this.nodesMap.has(capec)) {
          this.addNode({
            id: capec,
            type: "capec",
            label: capec,
            metadata: {},
          });
        }
        this.addEdge(f.id, capec, "EXPLOITS_CAPEC", 0.3);
      }
    }

    // 3. Synthesize Chained Vulnerability Edges (CHAINED_TO)
    // E.g., Information Leak / Credential Extraction -> Remote Code Execution / Shell
    const findingsList = assessment.findings;
    for (const f1 of findingsList) {
      for (const f2 of findingsList) {
        if (f1.id !== f2.id) {
          // If f1 is an authentication/key extraction flaw and f2 is an unauthenticated service/CRT execution flaw
          const f1IsKeyOrAuth =
            f1.classification.cwe.some((c) =>
              ["CWE-798", "CWE-259", "CWE-288", "CWE-319"].includes(c),
            ) || f1.name.includes("Private Key") || f1.name.includes("Password");

          const f2IsExecutionOrShell =
            f2.classification.cwe.some((c) =>
              ["CWE-242", "CWE-120", "CWE-78", "CWE-1191"].includes(c),
            ) || f2.name.includes("Function Call") || f2.name.includes("JTAG");

          if (f1IsKeyOrAuth && f2IsExecutionOrShell) {
            this.addEdge(f1.id, f2.id, "CHAINED_TO", 0.9);
          }
        }
      }
    }
  }

  /**
   * Search and formulate multi-hop attack paths.
   */
  public findAttackPaths(): readonly AttackPath[] {
    const paths: AttackPath[] = [];

    // Find all CHAINED_TO edges representing composite exploit chains
    const chainEdges = this.edgesList.filter((e) => e.relationship === "CHAINED_TO");

    for (let i = 0; i < chainEdges.length; i++) {
      const edge = chainEdges[i]!;
      const fromNode = this.nodesMap.get(edge.source);
      const toNode = this.nodesMap.get(edge.target);

      if (!fromNode || !toNode) continue;

      const pathId = `path_${createHash("sha256")
        .update(`${fromNode.id}:${toNode.id}:${i}`)
        .digest("hex")
        .slice(0, 16)}`;

      const step1: AttackPathStep = {
        fromNode,
        toNode,
        edge,
        explanation: `Initial step: Attacker leverages '${fromNode.label}' to bypass trust boundaries and obtain required credentials or access tokens.`,
      };

      const step2: AttackPathStep = {
        fromNode: toNode,
        toNode,
        edge,
        explanation: `Pivoting step: Attacker utilizes established access to trigger '${toNode.label}', escalating privileges or executing arbitrary commands.`,
      };

      const risk1 = fromNode.cvss_score ?? 7.0;
      const risk2 = toNode.cvss_score ?? 7.0;
      const cumulativeRisk = Math.min(risk1 + risk2 * 0.5, 10.0);

      let overallSeverity: SecuritySeverityLevel = "HIGH";
      if (cumulativeRisk >= 9.0) overallSeverity = "CRITICAL";
      else if (cumulativeRisk >= 7.0) overallSeverity = "HIGH";
      else if (cumulativeRisk >= 4.0) overallSeverity = "MEDIUM";
      else overallSeverity = "LOW";

      paths.push({
        path_id: pathId,
        title: `Composite Exploit Chain: ${fromNode.label} ➔ ${toNode.label}`,
        steps: [step1, step2],
        cumulative_risk: Number(cumulativeRisk.toFixed(1)),
        overall_severity: overallSeverity,
        narrative:
          `Multi-hop attack path identified. Adversary exploits '${fromNode.label}' ` +
          `(CVSS ${risk1}) to compromise access prerequisites, directly enabling the exploitation of ` +
          `'${toNode.label}' (CVSS ${risk2}), achieving an aggregate chain severity of ${overallSeverity} (${cumulativeRisk.toFixed(1)}/10.0).`,
      });
    }

    return paths;
  }

  /**
   * Evaluate exposure and risk to designated Crown Jewel assets.
   */
  public computeCrownJewelRisk(assessment: AssessmentState): CrownJewelRiskReport {
    const crownJewels = assessment.assets.filter(
      (a) =>
        a.tags.includes("critical") ||
        a.tags.includes("backend") ||
        Boolean(a.metadata.crown_jewel),
    );

    const attackPaths = this.findAttackPaths();
    let highestRisk = 0;

    for (const p of attackPaths) {
      if (p.cumulative_risk > highestRisk) {
        highestRisk = p.cumulative_risk;
      }
    }

    let verdict: CrownJewelRiskReport["posture_verdict"] = "RESILIENT";
    if (highestRisk >= 9.0) verdict = "COMPROMISED";
    else if (highestRisk >= 7.0) verdict = "HIGH_RISK";
    else if (highestRisk >= 4.0) verdict = "ELEVATED";

    return {
      crown_jewel_assets: crownJewels,
      reachable_paths: attackPaths,
      highest_path_risk: highestRisk,
      posture_verdict: verdict,
    };
  }
}


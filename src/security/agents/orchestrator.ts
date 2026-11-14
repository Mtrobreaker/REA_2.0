import { createHash } from "node:crypto";
import { ok, err, type Result } from "../../domain/result.js";
import {
  calculateAssessmentMetrics,
  type AssessmentPhase,
  type AssessmentState,
} from "../../domain/security/assessment.js";
import type { SecurityFinding } from "../../domain/security/finding.js";
import {
  SecurityKnowledgeGraph,
  type AttackPath,
} from "../graph/knowledgeGraph.js";
import type { PackBoardStore } from "../../domain/security/packboard/types.js";
import { BinaryAnalysisAgent } from "./binaryAnalysisAgent.js";
import { FirmwareSecurityAgent } from "./firmwareSecurityAgent.js";
import { HardwareSecurityAgent } from "./hardwareSecurityAgent.js";
import { MalwareAnalysisAgent } from "./malwareAnalysisAgent.js";
import { ReconnaissanceAgent } from "./reconnaissanceAgent.js";
import { RemediationAgent } from "./remediationAgent.js";
import { SoftwareSecurityAgent } from "./softwareSecurityAgent.js";
import { ThreatIntelligenceAgent } from "./threatIntelligenceAgent.js";
import type {
  AgentContext,
  AgentExecutionError,
  AgentExecutionResult,
  AgentMessage,
  AgentRole,
  SecurityAgent,
} from "./types.js";
import { VulnerabilityVerificationAgent } from "./verificationAgent.js";

export interface OrchestrationResult {
  readonly assessment: AssessmentState;
  readonly message_history: readonly AgentMessage[];
  readonly agent_logs: Readonly<Record<AgentRole, readonly string[]>>;
  readonly attack_paths: readonly AttackPath[];
}

export interface OrchestrationError {
  readonly phase: AssessmentPhase;
  readonly failing_agent: AgentRole;
  readonly message: string;
  readonly details?: unknown;
}

/**
 * Chief Security Orchestrator
 * Coordinates the 10-agent specialized cybersecurity team across all assessment phases:
 * Reconnaissance -> Vulnerability Discovery -> Threat Intelligence -> Verification -> Remediation -> Final Assessment.
 */
export class ChiefSecurityOrchestrator implements SecurityAgent {
  public readonly role = "orchestrator";
  public readonly name = "Chief Security Orchestrator";
  public readonly description =
    "Coordinates assessment workflow, assigns tasks to specialized agents, aggregates findings, and produces final security assessments.";

  private readonly agents: Readonly<Record<AgentRole, SecurityAgent>>;
  private readonly packboard?: PackBoardStore | undefined;

  constructor(
    customAgents?: Partial<Record<AgentRole, SecurityAgent>>,
    packboard?: PackBoardStore | undefined,
  ) {
    this.packboard = packboard;
    this.agents = {
      orchestrator: this,
      reconnaissance: customAgents?.reconnaissance ?? new ReconnaissanceAgent(),
      software_security:
        customAgents?.software_security ?? new SoftwareSecurityAgent(),
      binary_analysis:
        customAgents?.binary_analysis ?? new BinaryAnalysisAgent(),
      firmware_security:
        customAgents?.firmware_security ?? new FirmwareSecurityAgent(),
      hardware_security:
        customAgents?.hardware_security ?? new HardwareSecurityAgent(),
      malware_analysis:
        customAgents?.malware_analysis ?? new MalwareAnalysisAgent(),
      verification:
        customAgents?.verification ?? new VulnerabilityVerificationAgent(),
      threat_intelligence:
        customAgents?.threat_intelligence ?? new ThreatIntelligenceAgent(),
      remediation: customAgents?.remediation ?? new RemediationAgent(),
    };
  }

  /**
   * Execute single agent pass (implements SecurityAgent).
   */
  public async execute(
    _context: AgentContext,
  ): Promise<Result<AgentExecutionResult, AgentExecutionError>> {
    return ok({
      agent_role: this.role,
      actions_performed: ["Orchestrator pass executed"],
      findings_added: [],
      findings_modified: [],
      assets_added: [],
    });
  }

  /**
   * Run end-to-end multi-agent cybersecurity assessment.
   */
  public async runAssessment(
    initialState: AssessmentState,
    signal?: AbortSignal,
  ): Promise<Result<OrchestrationResult, OrchestrationError>> {
    let currentState: AssessmentState = { ...initialState };
    const messages: AgentMessage[] = [];
    const agentLogs: Record<AgentRole, string[]> = {
      orchestrator: [],
      reconnaissance: [],
      software_security: [],
      binary_analysis: [],
      firmware_security: [],
      hardware_security: [],
      malware_analysis: [],
      verification: [],
      threat_intelligence: [],
      remediation: [],
    };

    const postMessage = (msg: Omit<AgentMessage, "message_id" | "timestamp">) => {
      const timestamp = new Date().toISOString();
      const hash = createHash("sha256")
        .update(`${msg.sender}:${msg.recipient}:${timestamp}:${messages.length}`)
        .digest("hex");
      messages.push({
        ...msg,
        message_id: `msg_${hash}`,
        timestamp,
      });
    };

    const createContext = (): AgentContext => ({
      state: currentState,
      messages: [...messages],
      ...(signal !== undefined ? { signal } : {}),
      postMessage,
      updateAssessment: (updater) => {
        currentState = updater(currentState);
      },
      ...(this.packboard ? { packboard: this.packboard } : {}),
    });

    const runAgent = async (role: AgentRole): Promise<Result<void, OrchestrationError>> => {
      if (signal?.aborted) {
        return err({
          phase: currentState.phase,
          failing_agent: role,
          message: "Assessment aborted by operator cancellation signal.",
        });
      }

      const agent = this.agents[role];
      postMessage({
        sender: "orchestrator",
        recipient: role,
        kind: "TASK_ASSIGNMENT",
        payload: { target_phase: currentState.phase },
      });

      const res = await agent.execute(createContext());
      if (!res.ok) {
        postMessage({
          sender: role,
          recipient: "orchestrator",
          kind: "TASK_FAILURE",
          payload: res.error,
        });
        return err({
          phase: currentState.phase,
          failing_agent: role,
          message: `Agent ${role} failed: ${res.error.message}`,
          details: res.error,
        });
      }

      agentLogs[role].push(...res.value.actions_performed);
      return ok(undefined);
    };

    // --- Phase 1: Reconnaissance ---
    currentState = { ...currentState, phase: "reconnaissance" };
    agentLogs.orchestrator.push("Starting Phase 1: Reconnaissance");
    const reconRes = await runAgent("reconnaissance");
    if (!reconRes.ok) return reconRes;

    // --- Phase 2: Vulnerability Discovery ---
    currentState = { ...currentState, phase: "vulnerability_discovery" };
    agentLogs.orchestrator.push("Starting Phase 2: Vulnerability Discovery");

    const hasSource = currentState.assets.some((a) => a.type === "source_repository");
    const hasBinary = currentState.assets.some((a) => a.type === "compiled_binary");
    const hasFirmware = currentState.assets.some((a) => a.type === "firmware_image");
    const hasHardware = currentState.assets.some(
      (a) => a.type === "device_hardware" || a.type === "hardware_rtl",
    );

    if (hasSource) {
      const swRes = await runAgent("software_security");
      if (!swRes.ok) return swRes;
    }

    if (hasBinary) {
      const binRes = await runAgent("binary_analysis");
      if (!binRes.ok) return binRes;
    }

    if (hasFirmware) {
      const fwRes = await runAgent("firmware_security");
      if (!fwRes.ok) return fwRes;
    }

    if (hasHardware) {
      const hwRes = await runAgent("hardware_security");
      if (!hwRes.ok) return hwRes;
    }

    // Always run malware analysis across all detected assets
    const mwRes = await runAgent("malware_analysis");
    if (!mwRes.ok) return mwRes;

    // --- Phase 3: Threat Intelligence Correlation ---
    agentLogs.orchestrator.push("Starting Phase 3: Threat Intelligence Correlation");
    const tiRes = await runAgent("threat_intelligence");
    if (!tiRes.ok) return tiRes;

    // --- Phase 4: Independent Verification ---
    currentState = { ...currentState, phase: "verification" };
    agentLogs.orchestrator.push("Starting Phase 4: Finding Verification & False-Positive Elimination");
    const vfRes = await runAgent("verification");
    if (!vfRes.ok) return vfRes;

    // --- Phase 5: Remediation Strategy ---
    currentState = { ...currentState, phase: "remediation" };
    agentLogs.orchestrator.push("Starting Phase 5: Remediation & Patch Formulation");
    const rmRes = await runAgent("remediation");
    if (!rmRes.ok) return rmRes;

    // --- Phase 6: Final Synthesis & Completion ---
    // Deduplicate findings
    const dedupedFindingsMap = new Map<string, SecurityFinding>();
    for (const f of currentState.findings) {
      dedupedFindingsMap.set(f.id, f);
    }
    const finalFindings = Array.from(dedupedFindingsMap.values());
    const finalMetrics = calculateAssessmentMetrics(
      currentState.assets,
      finalFindings,
    );

    currentState = {
      ...currentState,
      phase: "completed",
      completed_at: new Date().toISOString(),
      findings: finalFindings,
      metrics: finalMetrics,
    };

    // Synthesize multi-hop attack paths via SecurityKnowledgeGraph
    const knowledgeGraph = new SecurityKnowledgeGraph(currentState);
    const attackPaths = knowledgeGraph.findAttackPaths();

    agentLogs.orchestrator.push(
      `Assessment complete: ${finalFindings.length} findings, ${finalMetrics.verified_findings} verified across ${currentState.assets.length} assets. ${attackPaths.length} attack path(s) modeled.`,
    );

    return ok({
      assessment: currentState,
      message_history: messages,
      agent_logs: agentLogs,
      attack_paths: attackPaths,
    });
  }
}

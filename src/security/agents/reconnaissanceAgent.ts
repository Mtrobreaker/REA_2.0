import { stat, readdir } from "node:fs/promises";
import { basename, extname, join } from "node:path";
import { ok, err, type Result } from "../../domain/result.js";
import {
  computeAssetId,
  type AssetRecord,
  type AssetType,
} from "../../domain/security/asset.js";
import { validateTargetAuthorization } from "../../domain/security/authorization.js";
import type {
  AgentContext,
  AgentExecutionError,
  AgentExecutionResult,
  SecurityAgent,
} from "./types.js";

/**
 * Reconnaissance Agent
 * Identifies authorized assets, categorizes technologies, maps entrypoints, and registers asset inventory.
 */
export class ReconnaissanceAgent implements SecurityAgent {
  public readonly role = "reconnaissance";
  public readonly name = "Reconnaissance & Attack Surface Agent";
  public readonly description =
    "Discovers authorized target components, inventories technologies, and maps exposed entry points.";

  public async execute(
    context: AgentContext,
  ): Promise<Result<AgentExecutionResult, AgentExecutionError>> {
    const scope = context.state.scope;
    const discoveredAssets: AssetRecord[] = [];
    const actions: string[] = [];

    for (const target of scope.allowed_targets) {
      // 1. Fail-closed authorization check
      const auth = validateTargetAuthorization(target, scope);
      if (!auth.ok) {
        return err({
          agent_role: this.role,
          code: "TARGET_UNAUTHORIZED",
          message: `Target ${target} failed authorization check: ${auth.error.message}`,
        });
      }

      actions.push(`Inspecting target path: ${target}`);

      try {
        const stats = await stat(target);
        if (stats.isDirectory()) {
          const dirAsset = this.createAssetRecord(target, "source_repository", {
            is_directory: true,
          });
          discoveredAssets.push(dirAsset);

          // Sub-scan directory for specific binary or firmware files
          const subAssets = await this.scanDirectory(target, 2);
          discoveredAssets.push(...subAssets);
          actions.push(
            `Identified source repository with ${subAssets.length} embedded component asset(s)`,
          );
        } else if (stats.isFile()) {
          const type = this.inferAssetType(target);
          const fileAsset = this.createAssetRecord(target, type, {
            size_bytes: stats.size,
          });
          discoveredAssets.push(fileAsset);
          actions.push(
            `Identified singular asset ${fileAsset.name} as ${type}`,
          );
        }
      } catch (error: unknown) {
        // File may be virtual, unreadable, or missing
        actions.push(
          `Warning: Unable to access target ${target}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }

    // Update assessment with discovered assets
    if (discoveredAssets.length > 0) {
      context.updateAssessment((state) => ({
        ...state,
        assets: [...state.assets, ...discoveredAssets],
        metrics: {
          ...state.metrics,
          total_assets: state.assets.length + discoveredAssets.length,
        },
      }));
    }

    context.postMessage({
      sender: this.role,
      recipient: "orchestrator",
      kind: "TASK_COMPLETION",
      payload: {
        discovered_assets: discoveredAssets.map((a) => ({
          id: a.id,
          name: a.name,
          type: a.type,
        })),
      },
    });

    return ok({
      agent_role: this.role,
      actions_performed: actions,
      findings_added: [],
      findings_modified: [],
      assets_added: discoveredAssets,
    });
  }

  private inferAssetType(filePath: string): AssetType {
    const ext = extname(filePath).toLowerCase();
    switch (ext) {
      case ".bin":
      case ".img":
      case ".rom":
      case ".fw":
        return "firmware_image";
      case ".tty":
      case ".com":
      case ".dtb":
      case ".dts":
        return "device_hardware";
      case ".exe":
      case ".dll":
      case ".so":
      case ".dylib":
      case ".elf":
      case ".o":
        return "compiled_binary";
      default:
        return "source_repository";
    }
  }

  private createAssetRecord(
    path: string,
    type: AssetType,
    extraMetadata: Record<string, unknown> = {},
  ): AssetRecord {
    const name = basename(path);
    const id = computeAssetId({
      name,
      type,
    });

    return {
      id,
      name,
      type,
      path,
      digest: null,
      architecture: null,
      version: null,
      environment: null,
      tags: ["recon-discovered", type],
      metadata: extraMetadata,
    };
  }

  private async scanDirectory(
    dirPath: string,
    maxDepth: number,
  ): Promise<AssetRecord[]> {
    if (maxDepth <= 0) return [];
    const assets: AssetRecord[] = [];

    try {
      const entries = await readdir(dirPath, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.name.startsWith(".") || entry.name === "node_modules") {
          continue;
        }

        const fullPath = join(dirPath, entry.name);
        if (entry.isFile()) {
          const type = this.inferAssetType(fullPath);
          if (type !== "source_repository") {
            // Binary, firmware, or RTL within the source repo
            assets.push(this.createAssetRecord(fullPath, type));
          }
        }
      }
    } catch {
      // Ignore directory read errors
    }

    return assets;
  }
}

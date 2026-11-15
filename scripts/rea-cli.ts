#!/usr/bin/env node
/**
 * REA CLI Entrypoint for Security Commands (M1.1B)
 * Invokes `registerSecurityCommands` on the Incur CLI instance, serves `process.argv.slice(2)`,
 * and deterministically serializes command result envelopes as JSON on stdout.
 */
import pino from "pino";
import { Cli } from "incur";
import { registerSecurityCommands } from "../src/cli/securityCommands.js";
import type { CliInstance } from "../src/cli/types.js";

function writeStdoutFlushed(text: string): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    process.stdout.write(text, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

async function main(): Promise<void> {
  const logger = pino({ enabled: false });
  const rawCli = Cli.create("rea", {
    version: "6.7.0",
    description: "REA Security Assessment CLI",
  });

  let handledByCommand = false;

  const cliProxy: CliInstance = {
    command: (name: string, definition: any) => {
      const originalRun = definition.run;
      rawCli.command(name as any, {
        ...definition,
        run: async (context: any) => {
          const result = await originalRun(context);
          handledByCommand = true;
          if (
            result &&
            typeof result === "object" &&
            ((result as Record<string, unknown>).status === "FAILED" ||
              (result as Record<string, unknown>).status === "ERROR")
          ) {
            process.exitCode = 1;
          }
          await writeStdoutFlushed(`${JSON.stringify(result, null, 2)}\n`);
          return undefined;
        },
      });
      return cliProxy;
    },
  } as unknown as CliInstance;

  registerSecurityCommands(cliProxy, logger, process.env);

  try {
    await (rawCli as any).serve(process.argv.slice(2), {
      stdout: (output: string) => {
        if (!handledByCommand && output) {
          process.stdout.write(output);
        }
      },
      exit: (code: number) => {
        if (code !== 0) {
          process.exitCode = code;
        }
      },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await writeStdoutFlushed(
      `${JSON.stringify(
        {
          status: "FAILED",
          error_code: "CLI_EXECUTION_ERROR",
          error: message,
        },
        null,
        2,
      )}\n`,
    );
    process.exitCode = 1;
  }
}

void main();

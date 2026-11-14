import { BinaryWorkerRuntime } from "../security/binary/worker/BinaryWorkerRuntime.js";

/**
 * Isolated Binary Analysis Child Process Entrypoint.
 *
 * Invoked by parent process supervisors (e.g., BinaryWorkerSupervisor in Milestone 3).
 * Communicates exclusively through bounded NDJSON framing on stdin/stdout.
 * Diagnostic logs flow exclusively to stderr.
 */
const runtime = new BinaryWorkerRuntime({
  workerId: process.env.REA_BINARY_WORKER_ID,
  allowedRoot: process.env.REA_BINARY_ALLOWED_ROOT,
});

try {
  await runtime.start();
  process.exit(0);
} catch (cause) {
  process.stderr.write(
    `[binaryAnalysisWorkerProcess] Fatal error: ${cause instanceof Error ? cause.message : String(cause)}\n`,
  );
  process.exit(1);
}

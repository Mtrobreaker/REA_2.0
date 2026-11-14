import {
  BINARY_IPC_CONTROL_FRAME_MAX_BYTES,
  BINARY_IPC_DATA_FRAME_MAX_BYTES,
  BINARY_IPC_MAX_PENDING_BYTES,
  binaryWorkerIpcMessageSchema,
  type BinaryWorkerIpcMessage,
} from "./binaryWorkerProtocol.js";
import { err, ok, type Result } from "../../../domain/result.js";

// ============================================================================
// Framing Error Types
// ============================================================================

export type FramingErrorCode =
  | "FRAME_OVERSIZED"
  | "CONTROL_FRAME_OVERSIZED"
  | "INVALID_UTF8"
  | "MALFORMED_JSON"
  | "PROTOTYPE_POLLUTION"
  | "SCHEMA_VALIDATION_ERROR"
  | "FRAME_TRUNCATED"
  | "DUPLICATE_MESSAGE_ID";

export interface FramingError {
  readonly code: FramingErrorCode;
  readonly message: string;
  readonly frameBytes?: number;
  readonly details?: unknown;
}

export interface FramingOptions {
  readonly controlFrameMaxBytes?: number;
  readonly dataFrameMaxBytes?: number;
  readonly maxPendingBytes?: number;
  readonly trackMessageIds?: boolean;
}

// ============================================================================
// Prototype-Safe JSON Parser
// ============================================================================

/**
 * Parses JSON while actively rejecting prototype-polluting keys (__proto__, constructor, prototype).
 */
export function safeJsonParse<T = unknown>(jsonText: string): T {
  return JSON.parse(jsonText, (key, value) => {
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      throw new Error(`PROTOTYPE_POLLUTION_ATTEMPT: Disallowed property key '${key}'`);
    }
    return value;
  }) as T;
}

// ============================================================================
// Bounded NDJSON Binary Message Framer
// ============================================================================

const CONTROL_MESSAGE_KINDS = new Set([
  "WORKER_READY",
  "HEARTBEAT",
  "CANCEL",
  "CANCEL_ACK",
  "SHUTDOWN",
  "SHUTDOWN_ACK",
  "WORKER_ERROR",
]);

export class BinaryMessageFramer {
  private readonly controlFrameMaxBytes: number;
  private readonly dataFrameMaxBytes: number;
  private readonly maxPendingBytes: number;
  private readonly trackMessageIds: boolean;

  private pendingBuffer: Buffer = Buffer.alloc(0);
  private readonly seenMessageIds: Set<string> = new Set();
  private readonly textDecoder = new TextDecoder("utf-8", { fatal: true });

  constructor(options?: FramingOptions) {
    this.controlFrameMaxBytes =
      options?.controlFrameMaxBytes ?? BINARY_IPC_CONTROL_FRAME_MAX_BYTES;
    this.dataFrameMaxBytes =
      options?.dataFrameMaxBytes ?? BINARY_IPC_DATA_FRAME_MAX_BYTES;
    this.maxPendingBytes =
      options?.maxPendingBytes ?? BINARY_IPC_MAX_PENDING_BYTES;
    this.trackMessageIds = options?.trackMessageIds ?? true;
  }

  public getPendingByteLength(): number {
    return this.pendingBuffer.length;
  }

  public reset(): void {
    this.pendingBuffer = Buffer.alloc(0);
    this.seenMessageIds.clear();
  }

  /**
   * Pushes a new raw buffer chunk into the framer.
   * Extracts and validates all complete newline-delimited frames.
   *
   * If a single frame has a syntax/schema error, that error is returned
   * while subsequent valid frames in the stream are preserved.
   */
  public push(
    chunk: Buffer,
  ): Array<Result<BinaryWorkerIpcMessage, FramingError>> {
    // 1. Guard against unbounded buffering before newline
    if (this.pendingBuffer.length + chunk.length > this.maxPendingBytes) {
      // Find if there is a newline within budget
      const combined = Buffer.concat([this.pendingBuffer, chunk]);
      const newlineIdx = combined.indexOf(0x0a); // '\n'
      if (newlineIdx === -1 || newlineIdx > this.dataFrameMaxBytes) {
        this.pendingBuffer = Buffer.alloc(0);
        return [
          err({
            code: "FRAME_OVERSIZED",
            message: `Incoming frame exceeded maximum pending buffer limit of ${this.maxPendingBytes} bytes without newline`,
            frameBytes: combined.length,
          }),
        ];
      }
    }

    this.pendingBuffer =
      this.pendingBuffer.length === 0
        ? chunk
        : Buffer.concat([this.pendingBuffer, chunk]);

    const results: Array<Result<BinaryWorkerIpcMessage, FramingError>> = [];

    let newlineIdx: number;
    while ((newlineIdx = this.pendingBuffer.indexOf(0x0a)) !== -1) {
      // Extract raw frame bytes excluding '\n'
      let frameBytes = this.pendingBuffer.subarray(0, newlineIdx);

      // Strip optional '\r' if CRLF
      if (frameBytes.length > 0 && frameBytes[frameBytes.length - 1] === 0x0d) {
        frameBytes = frameBytes.subarray(0, frameBytes.length - 1);
      }

      // Advance pending buffer immediately so malformed frame does not corrupt subsequent parsing
      this.pendingBuffer = this.pendingBuffer.subarray(newlineIdx + 1);

      // Skip blank lines
      if (frameBytes.length === 0) {
        continue;
      }

      // Parse and validate the single frame
      const frameResult = this.parseFrame(frameBytes);
      results.push(frameResult);
    }

    return results;
  }

  /**
   * Signals EOF on the stream.
   * If any un-delimited bytes remain in the pending buffer, returns a FRAME_TRUNCATED error.
   */
  public end(): Array<Result<BinaryWorkerIpcMessage, FramingError>> {
    if (this.pendingBuffer.length === 0) {
      return [];
    }

    const unparsedBytes = this.pendingBuffer.length;
    this.pendingBuffer = Buffer.alloc(0);

    return [
      err({
        code: "FRAME_TRUNCATED",
        message: `Stream reached EOF with ${unparsedBytes} un-delimited pending bytes without terminal newline`,
        frameBytes: unparsedBytes,
      }),
    ];
  }

  /**
   * Parses a single extracted frame buffer into a validated BinaryWorkerIpcMessage.
   */
  private parseFrame(
    frameBytes: Buffer,
  ): Result<BinaryWorkerIpcMessage, FramingError> {
    const byteLen = frameBytes.length;

    // Check absolute data frame limit
    if (byteLen > this.dataFrameMaxBytes) {
      return err({
        code: "FRAME_OVERSIZED",
        message: `Frame size (${byteLen} bytes) exceeds maximum data frame ceiling of ${this.dataFrameMaxBytes} bytes`,
        frameBytes: byteLen,
      });
    }

    // 1. Strict UTF-8 validation
    let text: string;
    try {
      text = this.textDecoder.decode(frameBytes);
    } catch (cause) {
      return err({
        code: "INVALID_UTF8",
        message: `Frame contains invalid UTF-8 byte sequences: ${cause instanceof Error ? cause.message : String(cause)}`,
        frameBytes: byteLen,
      });
    }

    // 2. Safe JSON parsing with prototype pollution check
    let rawObj: unknown;
    try {
      rawObj = safeJsonParse(text);
    } catch (cause) {
      const msg = cause instanceof Error ? cause.message : String(cause);
      if (msg.includes("PROTOTYPE_POLLUTION_ATTEMPT")) {
        return err({
          code: "PROTOTYPE_POLLUTION",
          message: msg,
          frameBytes: byteLen,
        });
      }
      return err({
        code: "MALFORMED_JSON",
        message: `JSON syntax error in frame: ${msg}`,
        frameBytes: byteLen,
      });
    }

    if (!rawObj || typeof rawObj !== "object" || Array.isArray(rawObj)) {
      return err({
        code: "SCHEMA_VALIDATION_ERROR",
        message: "Message frame must be a JSON object",
        frameBytes: byteLen,
      });
    }

    // 3. Control frame size enforcement
    const kind = (rawObj as any).kind;
    if (typeof kind === "string" && CONTROL_MESSAGE_KINDS.has(kind)) {
      if (byteLen > this.controlFrameMaxBytes) {
        return err({
          code: "CONTROL_FRAME_OVERSIZED",
          message: `Control message '${kind}' (${byteLen} bytes) exceeds control frame ceiling of ${this.controlFrameMaxBytes} bytes`,
          frameBytes: byteLen,
        });
      }
    }

    // 4. Strict Zod Schema validation
    const parseResult = binaryWorkerIpcMessageSchema.safeParse(rawObj);
    if (!parseResult.success) {
      const firstIssue = parseResult.error.issues[0];
      const issuePath = firstIssue?.path.join(".") ?? "root";
      const issueMsg = firstIssue?.message ?? "Validation failed";
      return err({
        code: "SCHEMA_VALIDATION_ERROR",
        message: `Schema validation failed at '${issuePath}': ${issueMsg}`,
        details: parseResult.error.format(),
        frameBytes: byteLen,
      });
    }

    const message = parseResult.data;

    // 5. Duplicate Message ID Tracking
    if (this.trackMessageIds && message.messageId) {
      if (this.seenMessageIds.has(message.messageId)) {
        return err({
          code: "DUPLICATE_MESSAGE_ID",
          message: `Duplicate message ID '${message.messageId}' detected`,
          frameBytes: byteLen,
        });
      }
      this.seenMessageIds.add(message.messageId);
    }

    return ok(message);
  }

  /**
   * Serializes a validated BinaryWorkerIpcMessage into a newline-delimited UTF-8 Buffer frame.
   */
  public serialize(
    message: BinaryWorkerIpcMessage,
  ): Result<Buffer, FramingError> {
    // 1. Validate message schema
    const parseRes = binaryWorkerIpcMessageSchema.safeParse(message);
    if (!parseRes.success) {
      return err({
        code: "SCHEMA_VALIDATION_ERROR",
        message: `Cannot serialize invalid message: ${parseRes.error.message}`,
        details: parseRes.error.format(),
      });
    }

    // 2. Stringify to JSON
    const json = JSON.stringify(parseRes.data);
    const frameBuffer = Buffer.from(`${json}\n`, "utf8");
    const payloadBytes = frameBuffer.length - 1; // excluding '\n'

    // 3. Check byte limits
    if (CONTROL_MESSAGE_KINDS.has(message.kind)) {
      if (payloadBytes > this.controlFrameMaxBytes) {
        return err({
          code: "CONTROL_FRAME_OVERSIZED",
          message: `Serialized control frame '${message.kind}' (${payloadBytes} bytes) exceeds ceiling of ${this.controlFrameMaxBytes} bytes`,
          frameBytes: payloadBytes,
        });
      }
    } else {
      if (payloadBytes > this.dataFrameMaxBytes) {
        return err({
          code: "FRAME_OVERSIZED",
          message: `Serialized data frame (${payloadBytes} bytes) exceeds ceiling of ${this.dataFrameMaxBytes} bytes`,
          frameBytes: payloadBytes,
        });
      }
    }

    return ok(frameBuffer);
  }
}


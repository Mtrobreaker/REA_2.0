import { ok, type Result } from "../../../domain/result.js";
import type {
  DecodeOptions,
  DecodeResult,
  Instruction,
  InstructionDecoderProvider,
} from "./types.js";
import { InstructionDecodeError } from "./types.js";
import { CapstoneDecoderProvider } from "./CapstoneDecoderProvider.js";
import { InProcessInstructionDecoder } from "./InProcessInstructionDecoder.js";

export type { DecodeOptions, DecodeResult };

/**
 * Universal Instruction Decoder Facade.
 *
 * Dispatches instruction stream decoding across registered providers (Capstone,
 * in-process conforming decoder). Preserves backward compatibility while enforcing
 * fail-closed semantics on malformed bytes or unsupported architectures.
 */
export class InstructionDecoder {
  private readonly providers: InstructionDecoderProvider[];
  private readonly inProcessDecoder: InProcessInstructionDecoder;
  private readonly capstoneProvider: CapstoneDecoderProvider;

  constructor(options?: { readonly providers?: InstructionDecoderProvider[] }) {
    this.inProcessDecoder = new InProcessInstructionDecoder();
    this.capstoneProvider = new CapstoneDecoderProvider();
    this.providers = options?.providers ?? [
      this.capstoneProvider,
      this.inProcessDecoder,
    ];
  }

  public getProviders(): readonly InstructionDecoderProvider[] {
    return this.providers;
  }

  public getInProcessDecoder(): InProcessInstructionDecoder {
    return this.inProcessDecoder;
  }

  public getCapstoneProvider(): CapstoneDecoderProvider {
    return this.capstoneProvider;
  }

  /**
   * Safe decoding with explicit Result error typing for unsupported architectures.
   */
  public decodeSafe(
    bytes: Uint8Array,
    baseAddress: number,
    options: DecodeOptions,
  ): Result<DecodeResult, InstructionDecodeError> {
    let fallbackInfo: { isFallback: boolean; requestedProvider?: string; fallbackReason?: string } = {
      isFallback: false,
    };

    const effectivePreferred =
      options.preferredProvider ??
      process.env.REA_DEFAULT_DECODER_PROVIDER ??
      "InProcessInstructionDecoder";

    if (effectivePreferred) {
      const match = this.providers.find((p) => p.name === effectivePreferred);
      if (match) {
        if (match.canDecode(options)) {
          const res = match.decode(bytes, baseAddress, options);
          if (res.ok) {
            return res;
          }
        }
        // Provider was requested but cannot decode or is unavailable
        fallbackInfo = {
          isFallback: true,
          requestedProvider: effectivePreferred,
          fallbackReason: `Requested provider '${effectivePreferred}' is unavailable in the current runtime environment.`,
        };
      }
    }

    for (const p of this.providers) {
      if (p.canDecode(options)) {
        const res = p.decode(bytes, baseAddress, options);
        if (res.ok) {
          if (fallbackInfo.isFallback) {
            const wrapped: any = [...res.value.instructions];
            wrapped.outcome = res.value.outcome;
            wrapped.instructions = res.value.instructions;
            wrapped.architecture = res.value.architecture;
            wrapped.baseAddress = res.value.baseAddress;
            wrapped.totalBytes = res.value.totalBytes;
            wrapped.decodedBytes = res.value.decodedBytes;
            wrapped.provenance = {
              ...res.value.provenance,
              requestedProvider: fallbackInfo.requestedProvider,
              isFallback: true,
              fallbackReason: fallbackInfo.fallbackReason,
            };
            if (res.value.haltReason) wrapped.haltReason = res.value.haltReason;
            return ok(wrapped as DecodeResult);
          }
          return res;
        }
      }
    }

    const fallbackRes = this.inProcessDecoder.decode(bytes, baseAddress, options);
    if (fallbackRes.ok && fallbackInfo.isFallback) {
      const wrapped: any = [...fallbackRes.value.instructions];
      wrapped.outcome = fallbackRes.value.outcome;
      wrapped.instructions = fallbackRes.value.instructions;
      wrapped.architecture = fallbackRes.value.architecture;
      wrapped.baseAddress = fallbackRes.value.baseAddress;
      wrapped.totalBytes = fallbackRes.value.totalBytes;
      wrapped.decodedBytes = fallbackRes.value.decodedBytes;
      wrapped.provenance = {
        ...fallbackRes.value.provenance,
        requestedProvider: fallbackInfo.requestedProvider,
        isFallback: true,
        fallbackReason: fallbackInfo.fallbackReason,
      };
      if (fallbackRes.value.haltReason) wrapped.haltReason = fallbackRes.value.haltReason;
      return ok(wrapped as DecodeResult);
    }
    return fallbackRes;
  }

  /**
   * Standard decoding entry point. Fails closed to empty array if decoding fails.
   */
  public decode(
    bytes: Uint8Array,
    baseAddress: number,
    options: DecodeOptions,
  ): Instruction[] {
    const res = this.decodeSafe(bytes, baseAddress, options);
    if (!res.ok) {
      return [];
    }
    return [...res.value.instructions];
  }

  /**
   * Direct structured decoding returning full DecodeResult metadata and provenance.
   */
  public decodeResult(
    bytes: Uint8Array,
    baseAddress: number,
    options: DecodeOptions,
  ): DecodeResult {
    const res = this.decodeSafe(bytes, baseAddress, options);
    if (res.ok) {
      return res.value;
    }
    const failArr: any = [];
    failArr.outcome = res.error.outcome;
    failArr.instructions = [];
    failArr.architecture = options.architecture;
    failArr.baseAddress = baseAddress;
    failArr.totalBytes = bytes.byteLength;
    failArr.decodedBytes = 0;
    failArr.provenance = {
      actualProvider: "InstructionDecoder",
      requestedProvider: options.preferredProvider,
      isFallback: false,
      timestamp: Date.now(),
    };
    failArr.error = res.error;
    failArr.haltReason = res.error.message;
    return failArr as DecodeResult;
  }
}

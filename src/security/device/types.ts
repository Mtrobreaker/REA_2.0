import type { Result } from "../../domain/result.js";
import type {
  DeviceCapabilityProfile,
  DeviceInterfaceStatus,
  PhysicalInterfaceType,
} from "../../domain/security/device.js";

export interface DeviceProbeOptions {
  readonly target: string;
  readonly timeoutMs?: number;
  readonly baudRates?: readonly number[];
  readonly signal?: AbortSignal;
}

export interface DeviceProbeResult {
  readonly interface_type: PhysicalInterfaceType;
  readonly status: DeviceInterfaceStatus;
  readonly banner?: string;
  readonly raw_attributes: Readonly<Record<string, unknown>>;
}

export interface DeviceAdapterError {
  readonly code:
    | "DEVICE_NOT_FOUND"
    | "CONNECTION_REFUSED"
    | "TIMEOUT"
    | "PERMISSION_DENIED"
    | "PROBE_FAILED";
  readonly message: string;
  readonly details?: unknown;
}

export interface DeviceInterfaceAdapter {
  readonly interfaceType: PhysicalInterfaceType;
  probe(options: DeviceProbeOptions): Promise<Result<DeviceProbeResult, DeviceAdapterError>>;
}


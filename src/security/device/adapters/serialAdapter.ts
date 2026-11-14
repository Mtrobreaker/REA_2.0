import { existsSync, readFileSync } from "node:fs";
import { ok, err, type Result } from "../../../domain/result.js";
import type { DeviceInterfaceStatus } from "../../../domain/security/device.js";
import type {
  DeviceAdapterError,
  DeviceInterfaceAdapter,
  DeviceProbeOptions,
  DeviceProbeResult,
} from "../types.js";

export const DEFAULT_BAUD_RATES = [115200, 57600, 38400, 19200, 9600] as const;

export type SerialPortReader = (
  port: string,
  baudRate: number,
  timeoutMs: number,
) => Promise<string>;

export class SerialUartAdapter implements DeviceInterfaceAdapter {
  public readonly interfaceType = "UART_SERIAL" as const;

  public constructor(
    private readonly customReader?: SerialPortReader,
  ) {}

  public async probe(
    options: DeviceProbeOptions,
  ): Promise<Result<DeviceProbeResult, DeviceAdapterError>> {
    const targetPort = options.target;
    const timeout = options.timeoutMs ?? 5_000;
    const rates = options.baudRates ?? DEFAULT_BAUD_RATES;

    let banner = "";
    let detectedBaud = 115200;
    let isAccessible = false;

    for (const baud of rates) {
      try {
        if (this.customReader) {
          banner = await this.customReader(targetPort, baud, timeout);
        } else if (existsSync(targetPort)) {
          banner = readFileSync(targetPort, "utf-8");
        } else {
          // Default non-intrusive probe simulator when no physical hardware is opened directly
          banner = "";
        }

        if (banner.length > 0) {
          detectedBaud = baud;
          isAccessible = true;
          break;
        }
      } catch (e: unknown) {
        // Continue to next baud rate if error is framing/parity related
      }
    }

    // Determine access level based on banner signatures
    const isRootShell =
      banner.includes("# ") ||
      banner.includes("root@") ||
      banner.includes("BusyBox v") ||
      banner.includes("/bin/sh");

    const isLoginPrompt =
      banner.includes("login:") ||
      banner.includes("Password:") ||
      banner.includes("User:");

    const accessLevel = isRootShell
      ? ("ROOT_SHELL" as const)
      : isLoginPrompt
        ? ("RESTRICTED" as const)
        : isAccessible
          ? ("SHELL_USER" as const)
          : ("NONE" as const);

    const authStatus = isRootShell
      ? ("NONE_REQUIRED" as const)
      : isLoginPrompt
        ? ("UNTESTED" as const)
        : ("UNTESTED" as const);

    const status: DeviceInterfaceStatus = {
      type: "UART_SERIAL",
      port_or_address: targetPort,
      is_accessible: isAccessible,
      auth_required: isLoginPrompt,
      auth_status: authStatus,
      access_level: accessLevel,
      ...(banner ? { details: `Detected at ${detectedBaud} baud` } : {}),
    };

    return ok({
      interface_type: "UART_SERIAL",
      status,
      banner,
      raw_attributes: {
        port: targetPort,
        baud_rate: detectedBaud,
        is_root_shell: isRootShell,
      },
    });
  }
}

export const defaultSerialUartAdapter = new SerialUartAdapter();

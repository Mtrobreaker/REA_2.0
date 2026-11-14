import { VulnerabilityAdjudicationBridge } from "../VulnerabilityAdjudicationBridge.js";
import { kInternalTestBypassSymbol } from "./testSymbols.js";

/**
 * Isolated test-only adjudication bridge for evaluating multi-stage state matrices.
 * This class is strictly isolated in testing/ and NEVER exported in production.
 */
export class TestAdjudicationBridge extends VulnerabilityAdjudicationBridge {
  constructor() {
    super({ [kInternalTestBypassSymbol]: true } as any);
  }
}


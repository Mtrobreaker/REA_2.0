import { z } from "zod";

/**
 * Fencing token represents a monotonically increasing integer generated
 * by the Central Blackboard to order and fence distributed worker claims.
 * Used to reject stale, hung, or zombie workers attempting to mutate task results.
 */
export type FencingToken = number;

export const fencingTokenSchema = z
  .number()
  .int()
  .positive("Fencing token must be a strictly positive integer");

export function nextFencingToken(currentToken: number): FencingToken {
  if (!Number.isSafeInteger(currentToken) || currentToken < 0) {
    return 1;
  }
  return currentToken + 1;
}

export function validateFencingToken(
  activeToken: number,
  submittedToken: number,
): boolean {
  return activeToken === submittedToken;
}


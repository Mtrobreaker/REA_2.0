import type { Lead, LeadId } from "./types.js";

/**
 * Optimistic concurrency control failure.
 * Another agent modified or claimed the lead concurrently.
 */
export interface PackBoardCasConflictError {
  readonly code: "CAS_CONFLICT";
  readonly message: string;
  readonly lead_id: LeadId;
  readonly expected_version: number;
  readonly current_lead: Lead;
}

/**
 * Persistence layer failure (SQLite contention, disk IO, schema violation).
 */
export interface PackBoardStoreError {
  readonly code: "STORE_ERROR";
  readonly message: string;
  readonly sqlite_code?: string;
  readonly cause?: unknown;
}

/**
 * Lease expiration error when attempting to renew an expired claim.
 */
export interface PackBoardLeaseExpiredError {
  readonly code: "LEASE_EXPIRED";
  readonly message: string;
  readonly lead_id: LeadId;
  readonly expired_at: number;
}

export type PackBoardError =
  | PackBoardCasConflictError
  | PackBoardStoreError
  | PackBoardLeaseExpiredError;


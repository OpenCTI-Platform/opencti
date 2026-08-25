import { UnsupportedError } from '../../config/errors';
import { USER_MERGE_REGISTER, USER_MERGE_REGISTRY_VERSION, UserMergeDisposition, type UserMergeRegisterRow } from './userMerge-register';
import type { UserMergeHandler } from './userMerge-handler';
import { userMergeHandlers } from './userMerge-registry';

export interface UserMergeCoverageRow {
  row_id: string;
  entity: string;
  path: string;
  disposition: UserMergeDisposition;
  covered: boolean;
  /** Handler answering for the row, absent when nothing covers it. */
  handler?: string;
}

export interface UserMergeCoverage {
  registry_version: string;
  total: number;
  covered_count: number;
  uncovered_count: number;
  /**
   * Uncovered rows among those a handler is expected to claim. Reported next to
   * `uncovered_count` because the two legitimately differ: a complete coverage still leaves
   * the retained and out-of-scope rows uncovered, and an operator reading `uncovered_count: 18`
   * next to `is_complete: true` needs the number the gate actually reads.
   */
  gating_uncovered_count: number;
  /** True when nothing a handler must claim is left uncovered. Gates the source account deletion. */
  is_complete: boolean;
  rows: UserMergeCoverageRow[];
}

/**
 * Dispositions that a handler has to answer for.
 *
 * `retain` and `out-of-scope` are excluded by construction, not by tolerance: a retained row
 * is one the merge deliberately does not rewrite, an out-of-scope one is unreachable. No
 * handler will ever claim them, so counting them in would leave the deletion gate shut for
 * good — including once every remaining transfer is implemented.
 */
const GATING_DISPOSITIONS = [UserMergeDisposition.Transfer, UserMergeDisposition.Conditional];

const coverageRow = (row: UserMergeRegisterRow, handler?: string): UserMergeCoverageRow => ({
  row_id: row.id,
  entity: row.entity,
  path: row.path,
  disposition: row.disposition,
  covered: handler !== undefined,
  handler,
});

/**
 * What the merge covers and, above all, what it does not.
 *
 * The manifest is derived from the register rather than from the handlers, so an uncovered
 * row is named instead of being absent. A report built from the handlers alone can only show
 * what was done: with a partial handler set — the state of every intermediate build — it
 * would look complete while leaving most of the register untouched.
 *
 * `is_complete` is what a later chunk reads to decide whether deleting the source account is
 * legitimate. Deleting on a partial coverage would destroy the only remaining link to the
 * references no handler moved. It answers for the rows a handler must claim, not for the
 * whole register — see GATING_DISPOSITIONS.
 */
export const buildUserMergeCoverage = (
  handlers: UserMergeHandler[] = userMergeHandlers(),
  disposition?: UserMergeDisposition,
): UserMergeCoverage => {
  const claimedBy = new Map<string, string>();
  handlers.forEach((handler) => {
    handler.covers.forEach((rowId) => claimedBy.set(rowId, handler.identifier));
  });
  // Counts are always computed over the whole register: a filtered view must not be able to
  // report a complete coverage by narrowing the question.
  const allRows = USER_MERGE_REGISTER.map((row) => coverageRow(row, claimedBy.get(row.id)));
  const coveredCount = allRows.filter((row) => row.covered).length;
  const gatingUncovered = allRows.filter((row) => GATING_DISPOSITIONS.includes(row.disposition) && !row.covered);
  const rows = disposition ? allRows.filter((row) => row.disposition === disposition) : allRows;
  return {
    registry_version: USER_MERGE_REGISTRY_VERSION,
    total: allRows.length,
    covered_count: coveredCount,
    uncovered_count: allRows.length - coveredCount,
    gating_uncovered_count: gatingUncovered.length,
    is_complete: gatingUncovered.length === 0,
    rows,
  };
};

/**
 * The register uses kebab-case values; GraphQL enum values cannot contain a dash. The
 * mapping is explicit rather than derived from the string, so renaming one side is a
 * compilation error instead of a silently empty filter.
 */
const GRAPHQL_DISPOSITIONS: Record<string, UserMergeDisposition> = {
  TRANSFER: UserMergeDisposition.Transfer,
  INVALIDATE: UserMergeDisposition.Invalidate,
  CONDITIONAL: UserMergeDisposition.Conditional,
  RETAIN: UserMergeDisposition.Retain,
  OUT_OF_SCOPE: UserMergeDisposition.OutOfScope,
};

export const toRegisterDisposition = (value?: string | null): UserMergeDisposition | undefined => {
  if (!value) {
    return undefined;
  }
  const disposition = GRAPHQL_DISPOSITIONS[value];
  if (!disposition) {
    // Silently dropping the filter would answer a different question than the one asked, on
    // the very manifest that decides whether the source account may be deleted.
    throw UnsupportedError('Unknown merge register disposition', { disposition: value });
  }
  return disposition;
};

export const toGraphQLDisposition = (disposition: UserMergeDisposition): string => {
  const found = Object.keys(GRAPHQL_DISPOSITIONS).find((key) => GRAPHQL_DISPOSITIONS[key] === disposition);
  if (!found) {
    throw new Error(`Unmapped register disposition: ${disposition}`);
  }
  return found;
};

export interface UserMergeApiCoverageRow extends Omit<UserMergeCoverageRow, 'disposition'> {
  /**
   * A GraphQL enum value such as `TRANSFER`, deliberately not typed with the register enum:
   * its values are kebab-case, so a comparison against it would compile and never match.
   */
  disposition: string;
}

/** Coverage as the API exposes it: same content, GraphQL disposition values. */
export interface UserMergeApiCoverage extends Omit<UserMergeCoverage, 'rows'> {
  rows: UserMergeApiCoverageRow[];
}

export const buildApiUserMergeCoverage = (
  handlers?: UserMergeHandler[],
  disposition?: string | null,
): UserMergeApiCoverage => {
  const coverage = buildUserMergeCoverage(handlers, toRegisterDisposition(disposition));
  return {
    ...coverage,
    rows: coverage.rows.map((row) => ({ ...row, disposition: toGraphQLDisposition(row.disposition) })),
  };
};

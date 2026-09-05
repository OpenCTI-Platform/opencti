import { INDEX_DELETED_OBJECTS, READ_INDEX_DRAFT_OBJECTS, READ_PLATFORM_INDICES } from '../../database/utils';
import type { AuthContext, AuthUser } from '../../types/user';
import type { UserMergeOptions } from './userMerge-types';
import type { UserMergeProjectedRights, UserMergeRightsLabels } from './userMerge-rights';

/**
 * Index scope of every handler, defined once here rather than per handler.
 *
 * The platform indices, plus the trash and the drafts. Both hold copies that can come back:
 * the trash is restorable, a draft is validated. Leaving them untouched would re-inject source
 * ids into live data at that moment — including access control pointing at a user that no
 * longer exists. Stopping the workers does not flush the drafts, so the empty-platform
 * prerequisite does not cover them.
 *
 * Draft copies are produced by a reindex of the live document, so they carry the same fields
 * under the same names: the handler queries and scripts apply to them unchanged.
 */
export const USER_MERGE_TARGET_INDICES = [...READ_PLATFORM_INDICES, INDEX_DELETED_OBJECTS, READ_INDEX_DRAFT_OBJECTS];

/**
 * Identifier of the handler that closes the source account.
 *
 * Declared next to the contract rather than next to the handler: the registration guard is the
 * one place that has to name it, and importing the handler module from there would pull the
 * domain layer into a check that runs before any handler is loaded.
 */
export const USER_MERGE_SOURCE_DISABLE_HANDLER = 'source-deactivation';

/** One planned or applied change, as it appears in the report. */
export interface UserMergePlannedChange {
  /** Register row this change answers for. */
  register_row_id: string;
  entity_type: string;
  count: number;
  /**
   * Whether `count` is exact or estimated. Anything that changes the security posture —
   * rights, markings, organizations, anonymous exposure — must be exact; those deltas are
   * pure reads, so exactness costs nothing in writes.
   */
  exact: boolean;
  detail?: string;
}

/** A rights, marking or organization difference the operator has to decide on. */
export interface UserMergeRightsAlert {
  register_row_id: string;
  kind: 'rights' | 'marking' | 'organization' | 'exposure';
  message: string;
  /**
   * When true, the real pass refuses to write until the operator acknowledges the change.
   *
   * The refusal belongs to the engine rather than to `apply()`: raising it there would stop
   * the merge after earlier handlers already wrote, and raising it in `compute()` would keep
   * the difference out of the dry-run report — which is the one place the operator can read
   * it before deciding.
   */
  blocking?: boolean;
}

/**
 * What a handler computed from reading the platform. Stable and serializable: it is review
 * material in dry mode and the record of what was done in real mode.
 */
export interface UserMergeHandlerPlan {
  handler: string;
  changes: UserMergePlannedChange[];
  alerts: UserMergeRightsAlert[];
}

/** What a handler actually wrote. Same shape as the plan, plus the bulk write counters. */
export interface UserMergeHandlerOutcome extends UserMergeHandlerPlan {
  updated: number;
}

export interface UserMergeHandlerContext {
  context: AuthContext;
  sourceId: string;
  targetId: string;
  options: UserMergeOptions;
  /** Both users, resolved once by the engine. Never optional: see `rights`. */
  sourceUser: AuthUser;
  targetUser: AuthUser;
  /**
   * The rights of each user, and the rights the target holds once the strategy is applied.
   *
   * Computed once by the engine rather than by each handler: every handler computes before any
   * handler writes, so a handler asking the platform what the target can access would only ever
   * get the pre-merge answer. Passing the projection keeps the read/write disjointness rule
   * intact — the handler that writes the memberships is not read by the ones that need them.
   *
   * Required on purpose. A handler that had to cope with a missing projection would skip its
   * blocking alerts while the merge carried on, which is a security check failing open; the
   * engine aborts instead, so that shape cannot be written here.
   */
  rights: UserMergeRightsProjection;
  /**
   * When the *first* run on this pair began, not when the current one did.
   *
   * The merge writes activity traces of its own — the source disablement, and the
   * "A merged into B" record the requirements ask for. Both name the source by construction, so
   * a history rewrite that swept indiscriminately would erase the very proof of the operation.
   * Handlers reading the history index cut on this instead of naming those traces: a structural
   * boundary covers the ones we have not thought of, and makes a replay a no-op on them.
   *
   * Anchoring on the current run would only hide the traces of the run in progress. The deletion
   * gate runs a fresh dry-run, so the previous merge's own traces would fall back under the cut,
   * count as references still pending, and the gate could never open.
   */
  mergeStartedAt: Date;
}

export interface UserMergeRightsProjection {
  source: UserMergeProjectedRights;
  target: UserMergeProjectedRights;
  projected: UserMergeProjectedRights;
  labels: UserMergeRightsLabels;
}

/**
 * A category of merge work.
 *
 * The contract deliberately does not expose `dryRun()` and `run()` as two methods a handler
 * writes. It exposes one read-only `compute()` and one write-only `apply()`, and the engine
 * derives both modes from them: dry is `compute`, real is `compute` then `apply`.
 *
 * The precedent in the platform — `SanityOperation` — does expose both methods, and relies
 * on each implementation happening to call the same helper. That is a convention, and
 * conventions drift the day someone fixes a bug in one branch and forgets the other. Here
 * there is only one selection function, so "dry-run == real impact" cannot drift: a handler
 * has no second code path to drift into.
 */
export interface UserMergeHandler {
  /** Stable identifier, used in the journal and in the report. */
  identifier: string;
  /** Register rows this handler answers for. */
  covers: string[];
  /** Field paths this handler reads. Used for the disjointness check. */
  reads: string[];
  /** Field paths this handler writes. Used for the disjointness check. */
  writes: string[];
  /** Pure reads. Must not write anything. */
  compute: (handlerContext: UserMergeHandlerContext) => Promise<UserMergeHandlerPlan>;
  /**
   * Applies the plan. Must be idempotent: replaying it on an already-merged state is a
   * no-op, not a second write. It is not free everywhere — `creator_id` is `multiple:true`,
   * so an unguarded append duplicates the target id on every execution.
   */
  apply: (handlerContext: UserMergeHandlerContext, plan: UserMergeHandlerPlan) => Promise<number>;
}

/** Dry mode: the computation, and nothing else. */
export const handlerDryRun = async (
  handler: UserMergeHandler,
  handlerContext: UserMergeHandlerContext,
): Promise<UserMergeHandlerOutcome> => {
  const plan = await handler.compute(handlerContext);
  return { ...plan, updated: 0 };
};

/**
 * Order-independent signature of a plan, used by the engine to prove that what the real
 * pass is about to write is what the dry pass showed the operator.
 */
const changeKeys = (plan: UserMergeHandlerPlan): string[] => [...plan.changes]
  .map((change) => `${change.register_row_id}|${change.entity_type}|${change.count}|${change.exact}`)
  .sort();

const alertKeys = (plan: UserMergeHandlerPlan): string[] => [...plan.alerts]
  .map((alert) => `${alert.register_row_id}|${alert.kind}|${alert.message}|${alert.blocking === true}`)
  .sort();

export const planFingerprint = (plan: UserMergeHandlerPlan): string => JSON.stringify({
  handler: plan.handler,
  changes: changeKeys(plan),
  alerts: alertKeys(plan),
});

/**
 * What differs between the two passes, computed with the same normalisation as the
 * fingerprint so an entry listed here is exactly what made the two prints differ.
 *
 * Stating that the platform moved without naming what moved leaves the operator with a
 * refusal and no lead: the register row that changed is what tells them which activity
 * was still running.
 */
export const planDivergence = (dry: UserMergeHandlerPlan, real: UserMergeHandlerPlan): { dry_only: string[]; real_only: string[] } => {
  const before = [...changeKeys(dry), ...alertKeys(dry)];
  const after = [...changeKeys(real), ...alertKeys(real)];
  return {
    dry_only: before.filter((entry) => !after.includes(entry)),
    real_only: after.filter((entry) => !before.includes(entry)),
  };
};

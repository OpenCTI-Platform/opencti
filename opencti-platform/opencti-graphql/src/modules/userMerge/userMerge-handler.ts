import { INDEX_DELETED_OBJECTS, READ_INDEX_DRAFT_OBJECTS, READ_PLATFORM_INDICES } from '../../database/utils';
import type { AuthContext } from '../../types/user';
import type { UserMergeOptions } from './userMerge-types';

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
  /** Register version this handler was written against. */
  registryVersion: string;
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
export const planFingerprint = (plan: UserMergeHandlerPlan): string => {
  const changes = [...plan.changes]
    .map((change) => `${change.register_row_id}|${change.entity_type}|${change.count}|${change.exact}`)
    .sort();
  const alerts = [...plan.alerts]
    .map((alert) => `${alert.register_row_id}|${alert.kind}|${alert.message}`)
    .sort();
  return JSON.stringify({ handler: plan.handler, changes, alerts });
};

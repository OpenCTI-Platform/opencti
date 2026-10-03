import { userMergeBulkRewrite, type UserMergeRewriteCandidate, userMergeScanForRewrite } from './userMerge-bulk';
import {
  type UserMergeHandler,
  type UserMergeHandlerContext,
  type UserMergeHandlerPlan,
  type UserMergePlannedChange,
  type UserMergeRightsAlert,
  USER_MERGE_TARGET_INDICES,
} from './userMerge-handler';
import { remapUserInSerializedFilters } from './userMerge-filterRemap';
import {
  USER_MERGE_FILTER_ACKNOWLEDGED_ROWS,
  USER_MERGE_FILTER_TARGETS,
  type UserMergeFilterTarget,
  userMergeFilterCoveredRows,
  userMergeFilterFieldPaths,
} from './userMerge-filterTargets';

export const USER_MERGE_FILTERS_HANDLER = 'filter-user-references';

interface PirCriterion {
  filters: string;
  weight: number;
}

/**
 * Why a document holding the source id was left untouched.
 *
 * `unparsable` is a filter the platform cannot read back. `textual` is a filter that reads back
 * fine but carries the id inside a value rather than as one — someone typed the raw uuid into a
 * free-text search. Neither is rewritten, and the two are reported apart because they call for
 * opposite follow-ups.
 */
type RewriteRejection = 'unparsable' | 'textual';

interface TargetRewrite {
  candidate: UserMergeRewriteCandidate;
  doc: Record<string, unknown>;
  /** PIR criteria that became identical once remapped and were folded into one. */
  mergedCriteria: number;
}

export type { TargetRewrite };

interface TargetOutcome {
  rewrites: TargetRewrite[];
  /** Documents holding the source id in a field the platform cannot parse back. */
  unparsable: number;
  /** Documents whose filter mentions the source id as free text, not as a filter value. */
  textual: number;
  /** Documents in a lifecycle state the merge precondition rules out. */
  active: number;
}

/**
 * Documents whose filter field mentions the source id.
 *
 * The serialized filter fields map to `text` with no keyword sub-field, so a term query never
 * matches. The standard analyzer splits the id on its dashes, which makes a phrase match on the
 * id a match on that token sequence — a pre-selection, confirmed value by value once parsed.
 *
 * `pir_criteria` is the exception: it maps to `flattened`, whose leaves are indexed as whole
 * unanalyzed keywords, so no phrase match on a substring of the serialized filter can ever hit.
 * Every PIR is read instead and discarded in memory, which the entity's volume affords.
 */
const selectionQuery = (target: UserMergeFilterTarget, sourceId: string): Record<string, unknown> => {
  const must: Record<string, unknown>[] = [{ terms: { 'entity_type.keyword': [target.entityType] } }];
  if (target.shape === 'field') {
    must.push({ match_phrase: { [target.path]: sourceId } });
  }
  return { bool: { must } };
};

const isActive = (target: UserMergeFilterTarget, source: Record<string, any>): boolean => {
  if (!target.activity) {
    return false;
  }
  const matches = source[target.activity.path] === target.activity.equals;
  return target.activity.negate ? !matches : matches;
};

/**
 * Fold the criteria a remap made identical, keeping the highest weight.
 *
 * `computePirScore` counts a match once per distinct filter string but divides by the sum of
 * every criterion weight, so two criteria that differed only by the user they named would
 * deflate every score of that PIR once merged into the same string. Keeping the highest weight
 * rather than the sum leaves the PIR's scale untouched; the operator is alerted either way,
 * because no arithmetic here can guess what the two criteria were meant to weigh together.
 */
const foldCriteria = (criteria: PirCriterion[]): { criteria: PirCriterion[]; merged: number } => {
  const byFilters = new Map<string, PirCriterion>();
  let merged = 0;
  criteria.forEach((criterion) => {
    const existing = byFilters.get(criterion.filters);
    if (!existing) {
      byFilters.set(criterion.filters, criterion);
      return;
    }
    merged += 1;
    byFilters.set(criterion.filters, { ...existing, weight: Math.max(existing.weight, criterion.weight) });
  });
  return { criteria: Array.from(byFilters.values()), merged };
};

/**
 * The PIR criteria path: remap each criterion's own filter, then fold the ones a remap made
 * identical. Exported because this is where the merge can silently change a PIR's scoring.
 */
export const rewriteUserInPirCriteria = (
  candidate: UserMergeRewriteCandidate,
  target: UserMergeFilterTarget,
  sourceId: string,
  targetId: string,
): TargetRewrite | RewriteRejection | undefined => {
  const criteria = candidate.source[target.path];
  if (!Array.isArray(criteria)) {
    return undefined;
  }
  let changed = false;
  let rejection: RewriteRejection | undefined;
  const remapped: PirCriterion[] = criteria.map((criterion: PirCriterion) => {
    const raw = criterion?.filters;
    if (typeof raw !== 'string' || !raw.includes(sourceId)) {
      return criterion;
    }
    const result = remapUserInSerializedFilters(raw, sourceId, targetId);
    if (!result.changed) {
      rejection = result.parsed ? 'textual' : 'unparsable';
      return criterion;
    }
    changed = true;
    return { ...criterion, filters: result.filters };
  });
  if (!changed) {
    return rejection;
  }
  const folded = foldCriteria(remapped);
  return { candidate, doc: { [target.path]: folded.criteria }, mergedCriteria: folded.merged };
};

const rewriteField = (
  candidate: UserMergeRewriteCandidate,
  target: UserMergeFilterTarget,
  sourceId: string,
  targetId: string,
): TargetRewrite | RewriteRejection | undefined => {
  const raw = candidate.source[target.path];
  if (typeof raw !== 'string' || !raw.includes(sourceId)) {
    return undefined;
  }
  const result = remapUserInSerializedFilters(raw, sourceId, targetId);
  if (!result.changed) {
    return result.parsed ? 'textual' : 'unparsable';
  }
  return { candidate, doc: { [target.path]: result.filters }, mergedCriteria: 0 };
};

/**
 * What one target has to rewrite.
 *
 * The same function backs the dry pass and the real one, so what the operator reads is what
 * gets written: the count of a change is the length of the rewrite list, not an estimate.
 */
const resolveTarget = async (
  handlerContext: UserMergeHandlerContext,
  target: UserMergeFilterTarget,
): Promise<TargetOutcome> => {
  const { context, sourceId, targetId } = handlerContext;
  const candidates = await userMergeScanForRewrite(context, USER_MERGE_TARGET_INDICES, selectionQuery(target, sourceId));
  const outcome: TargetOutcome = { rewrites: [], unparsable: 0, textual: 0, active: 0 };
  candidates.forEach((candidate) => {
    const rewrite = target.shape === 'criteria-array'
      ? rewriteUserInPirCriteria(candidate, target, sourceId, targetId)
      : rewriteField(candidate, target, sourceId, targetId);
    if (rewrite === 'unparsable') {
      outcome.unparsable += 1;
      return;
    }
    if (rewrite === 'textual') {
      outcome.textual += 1;
      return;
    }
    if (!rewrite) {
      return;
    }
    outcome.rewrites.push(rewrite);
    if (isActive(target, candidate.source)) {
      outcome.active += 1;
    }
  });
  return outcome;
};

const alertsForTarget = (target: UserMergeFilterTarget, outcome: TargetOutcome): UserMergeRightsAlert[] => {
  const alerts: UserMergeRightsAlert[] = [];
  if (outcome.active > 0) {
    alerts.push({
      register_row_id: target.registerRow,
      kind: 'rights',
      message: `${outcome.active} ${target.entityType}(s) were active while the platform was expected to be at rest`,
    });
  }
  if (outcome.unparsable > 0) {
    alerts.push({
      register_row_id: target.registerRow,
      kind: 'rights',
      message: `${outcome.unparsable} ${target.entityType}(s) hold the source id in a ${target.path} the platform cannot parse, and were left untouched`,
    });
  }
  if (outcome.textual > 0) {
    alerts.push({
      register_row_id: target.registerRow,
      kind: 'rights',
      message: `${outcome.textual} ${target.entityType}(s) mention the source id inside a ${target.path} value rather than as one, and were left untouched: review them by hand`,
    });
  }
  const mergedCriteria = outcome.rewrites.reduce((total, rewrite) => total + rewrite.mergedCriteria, 0);
  if (mergedCriteria > 0) {
    alerts.push({
      register_row_id: target.registerRow,
      kind: 'rights',
      message: `${mergedCriteria} PIR criteria became identical once remapped and were folded into one, keeping the highest weight: review the PIR weighting`,
    });
  }
  return alerts;
};

/**
 * Rewrites the user references held inside the stored filters.
 *
 * The selection is by value, not by filter key. An `internal_id` is a random v4 that nothing in
 * the schema derives, so a value equal to the source id is a reference to the source user
 * whichever key carries it — and no list of user-bearing keys exists to select from anyway.
 * The comparison is on the whole value, so an id embedded in a longer string is never touched.
 *
 * The rewrite is structural rather than a substitution on the serialized string: a filter
 * naming both users would otherwise end up holding the target id twice, which deflates every
 * score of a PIR and duplicates a React key in the filter chips of the UI.
 */
export const userMergeFiltersHandler: UserMergeHandler = {
  identifier: USER_MERGE_FILTERS_HANDLER,
  get covers() {
    return userMergeFilterCoveredRows();
  },
  get reads() {
    return userMergeFilterFieldPaths();
  },
  get writes() {
    return userMergeFilterFieldPaths();
  },
  compute: async (handlerContext: UserMergeHandlerContext): Promise<UserMergeHandlerPlan> => {
    const changes: UserMergePlannedChange[] = [];
    const alerts: UserMergeRightsAlert[] = [];
    for (let i = 0; i < USER_MERGE_FILTER_TARGETS.length; i += 1) {
      const target = USER_MERGE_FILTER_TARGETS[i];

      const outcome = await resolveTarget(handlerContext, target);
      changes.push({
        register_row_id: target.registerRow,
        entity_type: target.entityType,
        count: outcome.rewrites.length,
        exact: true,
        detail: target.path,
      });
      alerts.push(...alertsForTarget(target, outcome));
    }
    USER_MERGE_FILTER_ACKNOWLEDGED_ROWS.forEach((row) => {
      changes.push({
        register_row_id: row.registerRow,
        entity_type: 'InternalFile',
        count: 0,
        exact: true,
        detail: row.reason,
      });
    });
    return { handler: USER_MERGE_FILTERS_HANDLER, changes, alerts };
  },
  apply: async (handlerContext: UserMergeHandlerContext, plan: UserMergeHandlerPlan): Promise<number> => {
    const planned = new Set(plan.changes.filter((change) => change.count > 0).map((change) => change.register_row_id));
    let updated = 0;
    for (let i = 0; i < USER_MERGE_FILTER_TARGETS.length; i += 1) {
      const target = USER_MERGE_FILTER_TARGETS[i];
      if (planned.has(target.registerRow)) {
        const outcome = await resolveTarget(handlerContext, target);
        const updates = outcome.rewrites.map((rewrite) => ({
          id: rewrite.candidate.id,
          index: rewrite.candidate.index,
          doc: rewrite.doc,
        }));

        updated += await userMergeBulkRewrite(handlerContext.context, target.id, updates);
      }
    }
    return updated;
  },
};

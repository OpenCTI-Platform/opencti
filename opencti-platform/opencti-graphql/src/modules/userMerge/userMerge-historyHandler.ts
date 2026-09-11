import { elRawCount } from '../../database/engine';
import { userMergeBulkUpdate } from './userMerge-bulk';
import { type UserMergeHandler, type UserMergeHandlerContext, type UserMergeHandlerPlan, type UserMergePlannedChange, USER_MERGE_TARGET_INDICES } from './userMerge-handler';
import { userMergeScalarQuery, userMergeScalarUpdateBody } from './userMerge-scalarQueries';
import type { UserMergeScalarTarget } from './userMerge-scalarTargets';
import { USER_MERGE_HISTORY_TARGETS, userMergeHistoryCoveredRows, userMergeHistoryFieldPaths } from './userMerge-historyTargets';

export const USER_MERGE_HISTORY_HANDLER = 'history-attribution';

const entityTypeLabel = (target: UserMergeScalarTarget): string => {
  return target.entityTypes ? target.entityTypes.join(', ') : '*';
};

const countTarget = async (target: UserMergeScalarTarget, sourceId: string): Promise<number> => {
  return elRawCount({
    index: USER_MERGE_TARGET_INDICES,
    body: { query: userMergeScalarQuery(target, sourceId) },
  });
};

/**
 * Re-attributes the past to the target user: who acted, on whose behalf, who the actors of a
 * described entity were, and who last changed each attribute of a document.
 *
 * History is not rewritten to hide anything — the events are unchanged, only the user they
 * point at is. Leaving them would break the reverse: the source user disappears, and every
 * screen resolving these ids would show an unknown actor instead of the person who acted.
 *
 * The targets are listed rather than discovered. `user_id` and `applicant_id` are visible to
 * the schema but are deliberately left out of the scalar handler so the history is decided
 * here as a whole, and `i_attributes.user_id` is invisible to it in any case since the
 * discovery does not walk into object mappings.
 */
export const userMergeHistoryHandler: UserMergeHandler = {
  identifier: USER_MERGE_HISTORY_HANDLER,
  covers: userMergeHistoryCoveredRows(),
  reads: userMergeHistoryFieldPaths(),
  writes: userMergeHistoryFieldPaths(),
  compute: async ({ sourceId }: UserMergeHandlerContext): Promise<UserMergeHandlerPlan> => {
    const changes: UserMergePlannedChange[] = [];
    for (let i = 0; i < USER_MERGE_HISTORY_TARGETS.length; i += 1) {
      const target = USER_MERGE_HISTORY_TARGETS[i];
      const count = await countTarget(target, sourceId);
      changes.push({
        register_row_id: target.registerRow,
        entity_type: entityTypeLabel(target),
        count,
        // A document count from the very query the rewrite runs on, so it is exact even for
        // the two targets holding several references per document.
        exact: true,
        detail: target.path,
      });
    }
    return { handler: USER_MERGE_HISTORY_HANDLER, changes, alerts: [] };
  },
  apply: async ({ sourceId, targetId }: UserMergeHandlerContext, plan: UserMergeHandlerPlan): Promise<number> => {
    const planned = new Set(plan.changes.filter((change) => change.count > 0).map((change) => `${change.register_row_id}|${change.detail}`));
    let updated = 0;
    for (let i = 0; i < USER_MERGE_HISTORY_TARGETS.length; i += 1) {
      const target = USER_MERGE_HISTORY_TARGETS[i];
      if (planned.has(`${target.registerRow}|${target.path}`)) {
        const result = await userMergeBulkUpdate(
          `${USER_MERGE_HISTORY_HANDLER}:${target.id}`,
          USER_MERGE_TARGET_INDICES,
          userMergeScalarUpdateBody(target, sourceId, targetId),
        );
        updated += result.updated;
      }
    }
    return updated;
  },
};

import { elRawCount } from '../../database/engine';
import { USER_MERGE_REGISTRY_VERSION } from './userMerge-register';
import { userMergeBulkUpdate } from './userMerge-bulk';
import {
  type UserMergeHandler,
  type UserMergeHandlerContext,
  type UserMergeHandlerPlan,
  type UserMergePlannedChange,
  type UserMergeRightsAlert,
  USER_MERGE_TARGET_INDICES,
} from './userMerge-handler';
import { userMergeScalarQuery, userMergeScalarUpdateBody } from './userMerge-scalarQueries';
import { userMergeScalarCoveredRows, userMergeScalarFieldPaths, userMergeScalarTargets, type UserMergeScalarTarget } from './userMerge-scalarTargets';

export const USER_MERGE_SCALAR_HANDLER = 'scalar-user-references';

const entityTypeLabel = (target: UserMergeScalarTarget): string => {
  return target.entityTypes ? target.entityTypes.join(', ') : '*';
};

const countTarget = async (target: UserMergeScalarTarget, sourceId: string): Promise<number> => {
  return elRawCount({
    index: USER_MERGE_TARGET_INDICES,
    body: { query: userMergeScalarQuery(target, sourceId) },
  });
};

const atRestAlert = (target: UserMergeScalarTarget, count: number): UserMergeRightsAlert => ({
  register_row_id: target.registerRow,
  kind: 'rights',
  message: `${count} document(s) matched ${target.id} while the platform was expected to be at rest`,
});

/**
 * Rewrites the user references held as plain fields on a document.
 *
 * Targets come from the schema: every attribute declared with format `id` and pointing at User.
 * The register cannot be derived from it, so a table alongside says what each discovered
 * attribute becomes — covered here, split on a lifecycle state, or left to another chunk — and
 * adds back the handful of fields the declarations do not expose.
 */
export const userMergeScalarHandler: UserMergeHandler = {
  identifier: USER_MERGE_SCALAR_HANDLER,
  get covers() {
    return userMergeScalarCoveredRows();
  },
  registryVersion: USER_MERGE_REGISTRY_VERSION,
  get reads() {
    return userMergeScalarFieldPaths();
  },
  get writes() {
    return userMergeScalarFieldPaths();
  },
  compute: async ({ sourceId }: UserMergeHandlerContext): Promise<UserMergeHandlerPlan> => {
    const changes: UserMergePlannedChange[] = [];
    const alerts: UserMergeRightsAlert[] = [];
    const targets = userMergeScalarTargets();
    for (let i = 0; i < targets.length; i += 1) {
      const target = targets[i];
      const count = await countTarget(target, sourceId);
      // Emitted even at zero: the report has to name what was examined, not only what moved.
      changes.push({
        register_row_id: target.registerRow,
        entity_type: entityTypeLabel(target),
        count,
        exact: true,
        detail: target.path,
      });
      if (target.unexpectedAtRest && count > 0) {
        alerts.push(atRestAlert(target, count));
      }
    }
    return { handler: USER_MERGE_SCALAR_HANDLER, changes, alerts };
  },
  apply: async ({ sourceId, targetId }: UserMergeHandlerContext, plan: UserMergeHandlerPlan): Promise<number> => {
    const planned = new Set(plan.changes.filter((change) => change.count > 0).map((change) => `${change.register_row_id}|${change.detail}`));
    let updated = 0;
    const targets = userMergeScalarTargets();
    for (let i = 0; i < targets.length; i += 1) {
      const target = targets[i];
      if (planned.has(`${target.registerRow}|${target.path}`)) {
        const result = await userMergeBulkUpdate(
          `${USER_MERGE_SCALAR_HANDLER}:${target.id}`,
          USER_MERGE_TARGET_INDICES,
          userMergeScalarUpdateBody(target, sourceId, targetId),
        );
        updated += result.updated;
      }
    }
    return updated;
  },
};

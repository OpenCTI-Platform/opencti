import { INGESTION_DEDUPLICATION_FEATURE_FLAG, isFeatureEnabled } from '../../config/conf';
import { UnsupportedError } from '../../config/errors';
import { createEntity, deleteElementById } from '../../database/middleware';
import { fullEntitiesList } from '../../database/middleware-loader';
import { SYSTEM_USER } from '../../utils/access';
import type { AuthContext } from '../../types/user';
import { type BasicStoreEntityIngestionDeduplicationRule, ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE } from '../ingestionDeduplication/ingestionDeduplicationRule-types';
import type { UserMergeHandler, UserMergeHandlerContext, UserMergeHandlerPlan, UserMergePlannedChange } from './userMerge-handler';

export const USER_MERGE_INGESTION_DEDUPLICATION_HANDLER = 'ingestion-deduplication-rules';

const REGISTER_ROW = 'ingestion-deduplication-rule.user-id';
const USER_FIELD = `${ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE}.user_id`;
const MOVED = 'moved to the target';
const DROPPED = 'dropped, the target keeps its own rule';

const loadUserRules = async (context: AuthContext, userId: string) => {
  const rules = await fullEntitiesList<BasicStoreEntityIngestionDeduplicationRule>(context, SYSTEM_USER, [ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE]);
  return rules.filter((rule) => rule.user_id === userId);
};

// A user has one rule per type: when both users have one, the target keeps its own
const splitSourceRules = async ({ context, sourceId, targetId }: UserMergeHandlerContext) => {
  const [sourceRules, targetRules] = await Promise.all([loadUserRules(context, sourceId), loadUserRules(context, targetId)]);
  const targetTypes = new Set(targetRules.map((rule) => rule.target_type));
  return {
    transferred: sourceRules.filter((rule) => !targetTypes.has(rule.target_type)),
    dropped: sourceRules.filter((rule) => targetTypes.has(rule.target_type)),
  };
};

// The type is in the detail so that the verified plan names each rule, not only how many there are
const ruleChange = (action: string, rule: BasicStoreEntityIngestionDeduplicationRule): UserMergePlannedChange => ({
  register_row_id: REGISTER_ROW,
  entity_type: ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE,
  count: 1,
  exact: true,
  detail: `${action}: ${rule.target_type}`,
});

/**
 * Moves the deduplication rules of the source to the target.
 *
 * Not left to the scalar rewrite: the rule id comes from its user and type, so a moved rule is
 * created again under the target, and a rule on a type the target already covers is dropped.
 */
export const userMergeIngestionDeduplicationHandler: UserMergeHandler = {
  identifier: USER_MERGE_INGESTION_DEDUPLICATION_HANDLER,
  covers: [REGISTER_ROW],
  reads: [USER_FIELD],
  writes: [USER_FIELD],
  compute: async (handlerContext: UserMergeHandlerContext): Promise<UserMergeHandlerPlan> => {
    const { transferred, dropped } = await splitSourceRules(handlerContext);
    // Without the flag no rule can be written: merging would leave the source rules behind its deleted account
    if (!isFeatureEnabled(INGESTION_DEDUPLICATION_FEATURE_FLAG) && transferred.length + dropped.length > 0) {
      throw UnsupportedError('The source user has ingestion deduplication rules: enable the INGESTION_DEDUPLICATION feature to merge them', {
        rule_count: transferred.length + dropped.length,
      });
    }
    const changes = [...transferred.map((rule) => ruleChange(MOVED, rule)), ...dropped.map((rule) => ruleChange(DROPPED, rule))];
    return {
      handler: USER_MERGE_INGESTION_DEDUPLICATION_HANDLER,
      changes: changes.length > 0 ? changes : [{ register_row_id: REGISTER_ROW, entity_type: ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE, count: 0, exact: true, detail: 'user_id' }],
      alerts: [],
    };
  },
  // Only the verified plan, and idempotent: a rule that changed side since stays on the source, where the deletion gate still sees it
  apply: async (handlerContext: UserMergeHandlerContext, plan: UserMergeHandlerPlan): Promise<number> => {
    const { context, targetId } = handlerContext;
    const planned = new Set(plan.changes.filter((change) => change.count > 0).map((change) => change.detail));
    const { transferred, dropped } = await splitSourceRules(handlerContext);
    const toMove = transferred.filter((rule) => planned.has(`${MOVED}: ${rule.target_type}`));
    const toDrop = dropped.filter((rule) => planned.has(`${DROPPED}: ${rule.target_type}`));
    for (let i = 0; i < toMove.length; i += 1) {
      const rule = toMove[i];
      const input = { user_id: targetId, target_type: rule.target_type, excluded_fields: rule.excluded_fields ?? [], ...(rule.ttl ? { ttl: rule.ttl } : {}) };
      await createEntity(context, SYSTEM_USER, input, ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE);
      await deleteElementById(context, SYSTEM_USER, rule.id, ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE);
    }
    for (let i = 0; i < toDrop.length; i += 1) {
      await deleteElementById(context, SYSTEM_USER, toDrop[i].id, ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE);
    }
    return toMove.length + toDrop.length;
  },
};

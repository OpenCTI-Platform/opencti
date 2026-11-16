import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { ENABLED_FEATURE_FLAGS } from '../../../../src/config/conf';
import { addUser } from '../../../../src/modules/user/user-domain';
import { deleteMergeableUser } from './userMerge-testFixtures';
import { deleteElementById } from '../../../../src/database/middleware';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { addIngestionDeduplicationRule } from '../../../../src/modules/ingestionDeduplication/ingestionDeduplicationRule-domain';
import {
  type BasicStoreEntityIngestionDeduplicationRule,
  ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE,
} from '../../../../src/modules/ingestionDeduplication/ingestionDeduplicationRule-types';
import type { UserMergeHandlerContext } from '../../../../src/modules/userMerge/userMerge-handler';
import { userMergeIngestionDeduplicationHandler } from '../../../../src/modules/userMerge/userMerge-ingestionDeduplicationHandler';
import { ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_MALWARE, ENTITY_TYPE_TOOL } from '../../../../src/schema/stixDomainObject';

// Read from the index: the handler writes below the domain layer, the cache follows only with the engine reset
const loadRules = async (userId: string) => {
  const rules = await fullEntitiesList<BasicStoreEntityIngestionDeduplicationRule>(testContext, ADMIN_USER, [ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE]);
  return rules.filter((rule) => rule.user_id === userId);
};

describe('userMerge ingestion deduplication handler', () => {
  let sourceId: string;
  let targetId: string;
  let handlerContext: UserMergeHandlerContext;

  beforeAll(async () => {
    sourceId = (await addUser(testContext, ADMIN_USER, { name: 'userMerge dedup source', password: 'userMerge', user_email: 'usermerge-dedup-source@opencti.invalid' })).id;
    targetId = (await addUser(testContext, ADMIN_USER, { name: 'userMerge dedup target', password: 'userMerge', user_email: 'usermerge-dedup-target@opencti.invalid' })).id;
    handlerContext = { context: testContext, sourceId, targetId } as unknown as UserMergeHandlerContext;
    await addIngestionDeduplicationRule(testContext, ADMIN_USER, { user_id: sourceId, target_type: ENTITY_TYPE_MALWARE, excluded_fields: ['modified'] });
    await addIngestionDeduplicationRule(testContext, ADMIN_USER, { user_id: sourceId, target_type: ENTITY_TYPE_TOOL, excluded_fields: ['modified'], ttl: 600 });
    await addIngestionDeduplicationRule(testContext, ADMIN_USER, { user_id: targetId, target_type: ENTITY_TYPE_MALWARE, excluded_fields: ['description'] });
  });

  afterAll(async () => {
    const rules = [...await loadRules(sourceId), ...await loadRules(targetId)];
    for (let i = 0; i < rules.length; i += 1) {
      await deleteElementById(testContext, ADMIN_USER, rules[i].id, ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE);
    }
    await deleteMergeableUser(sourceId);
    await deleteMergeableUser(targetId);
  });

  it('should refuse to merge rules while the feature is disabled', async () => {
    // GIVEN a source user with rules, and the feature disabled
    const enabledFlags = ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length);
    try {
      // WHEN the merge computes its plan
      const computing = userMergeIngestionDeduplicationHandler.compute(handlerContext);
      // THEN it is refused before anything is written, instead of leaving the rules behind the source account
      await expect(computing).rejects.toThrow('The source user has ingestion deduplication rules');
    } finally {
      ENABLED_FEATURE_FLAGS.push(...enabledFlags);
    }
    expect(await loadRules(sourceId)).toHaveLength(2);
  });

  it('should apply only the verified plan', async () => {
    // GIVEN a plan computed while the source has a campaign rule the target does not have
    const campaignRule = await addIngestionDeduplicationRule(testContext, ADMIN_USER, { user_id: sourceId, target_type: ENTITY_TYPE_CAMPAIGN });
    const plan = await userMergeIngestionDeduplicationHandler.compute(handlerContext);
    expect(plan.changes.map((change) => change.detail)).toContain(`moved to the target: ${ENTITY_TYPE_CAMPAIGN}`);
    // WHEN the target gets its own campaign rule before the plan is applied
    await addIngestionDeduplicationRule(testContext, ADMIN_USER, { user_id: targetId, target_type: ENTITY_TYPE_CAMPAIGN, excluded_fields: ['name'] });
    const onlyCampaign = { ...plan, changes: plan.changes.filter((change) => change.detail?.endsWith(ENTITY_TYPE_CAMPAIGN)) };
    // THEN the source rule is neither moved over the target rule nor dropped, since the plan said to move it
    expect(await userMergeIngestionDeduplicationHandler.apply(handlerContext, onlyCampaign)).toEqual(0);
    expect((await loadRules(sourceId)).map((rule) => rule.id)).toContain(campaignRule.id);
    const targetCampaign = (await loadRules(targetId)).find((rule) => rule.target_type === ENTITY_TYPE_CAMPAIGN);
    expect(targetCampaign?.excluded_fields).toEqual(['name']);
    await deleteElementById(testContext, ADMIN_USER, campaignRule.id, ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE);
    await deleteElementById(testContext, ADMIN_USER, targetCampaign?.id as string, ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE);
  });

  it('should move the source rules and keep the target rule on a shared type', async () => {
    // GIVEN a source with malware and tool rules, and a target with its own malware rule
    // WHEN the merge computes and applies its plan
    const plan = await userMergeIngestionDeduplicationHandler.compute(handlerContext);
    expect(plan.changes.map((change) => change.detail).sort()).toEqual([
      `dropped, the target keeps its own rule: ${ENTITY_TYPE_MALWARE}`,
      `moved to the target: ${ENTITY_TYPE_TOOL}`,
    ]);
    expect(await userMergeIngestionDeduplicationHandler.apply(handlerContext, plan)).toEqual(2);
    // THEN the tool rule is moved as it was, and the target keeps its own malware rule
    expect(await loadRules(sourceId)).toHaveLength(0);
    const targetRules = await loadRules(targetId);
    expect(targetRules).toHaveLength(2);
    const malware = targetRules.find((rule) => rule.target_type === ENTITY_TYPE_MALWARE);
    expect(malware?.excluded_fields).toEqual(['description']);
    const tool = targetRules.find((rule) => rule.target_type === ENTITY_TYPE_TOOL);
    expect(tool?.excluded_fields).toEqual(['modified']);
    expect(tool?.ttl).toEqual(600);
  });

  it('should change nothing when applied again', async () => {
    // GIVEN a merge already applied
    // WHEN it is computed and applied again
    const plan = await userMergeIngestionDeduplicationHandler.compute(handlerContext);
    // THEN nothing is planned nor written
    expect(plan.changes.map((change) => change.count)).toEqual([0]);
    expect(await userMergeIngestionDeduplicationHandler.apply(handlerContext, plan)).toEqual(0);
    expect(await loadRules(targetId)).toHaveLength(2);
  });
});

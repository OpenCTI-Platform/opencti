import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, buildStandardUser, testContext } from '../../../utils/testQuery';
import { addKillChainPhase, killChainPhaseDelete } from '../../../../src/domain/killChainPhase';
import { addAttackPattern } from '../../../../src/domain/attackPattern';
import { stixObjectMerge } from '../../../../src/domain/stix';
import { deleteElementById, storeLoadByIdWithRefs } from '../../../../src/database/middleware';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { ENTITY_TYPE_KILL_CHAIN_PHASE } from '../../../../src/schema/stixMetaObject';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../../../src/schema/stixDomainObject';
import type { BasicStoreEntity, StoreObject } from '../../../../src/types/store';

// Issue #19776: the Merge action of Settings > Taxonomies > Kill chain phases failed with "Unsupported entity type for merging"
describe('Kill chain phase merge', () => {
  let target: BasicStoreEntity;
  let source: BasicStoreEntity;
  let onSource: BasicStoreEntity;
  let onBoth: BasicStoreEntity;

  const phaseIdsOf = async (attackPatternId: string) => {
    const attackPattern = await storeLoadByIdWithRefs<StoreObject>(testContext, ADMIN_USER, attackPatternId);
    return ((attackPattern as any).killChainPhases ?? []).map((phase: BasicStoreEntity) => phase.internal_id);
  };

  beforeAll(async () => {
    target = await addKillChainPhase(testContext, ADMIN_USER, { kill_chain_name: 'merge-chain-target', phase_name: 'command-and-control', x_opencti_order: 1 });
    source = await addKillChainPhase(testContext, ADMIN_USER, { kill_chain_name: 'merge-chain-source', phase_name: 'command-and-control', x_opencti_order: 2 });
    onSource = await addAttackPattern(testContext, ADMIN_USER, { name: 'Kill chain merge on source', killChainPhases: [source.id] });
    onBoth = await addAttackPattern(testContext, ADMIN_USER, { name: 'Kill chain merge on both', killChainPhases: [target.id, source.id] });
  });

  afterAll(async () => {
    for (const attackPattern of [onSource, onBoth]) {
      await deleteElementById(testContext, ADMIN_USER, attackPattern.id, ENTITY_TYPE_ATTACK_PATTERN);
    }
    if (await storeLoadById(testContext, ADMIN_USER, target.id, ENTITY_TYPE_KILL_CHAIN_PHASE)) {
      await killChainPhaseDelete(testContext, ADMIN_USER, target.id);
    }
  });

  it('refuses the merge to a user who can merge knowledge but cannot manage kill chain phases', async () => {
    // The default standard user holds KNOWLEDGE_KNUPDATE_KNMERGE but not SETTINGS_SETKILLCHAINPHASES
    const knowledgeMerger = buildStandardUser([]);
    await expect(stixObjectMerge(testContext, knowledgeMerger, target.id, [source.id])).rejects.toThrowError('You are not allowed to merge kill chain phases.');
    // Nothing was written: the source and its refs are untouched
    expect(await storeLoadById(testContext, ADMIN_USER, source.internal_id, ENTITY_TYPE_KILL_CHAIN_PHASE)).toBeDefined();
    expect(await phaseIdsOf(onSource.id)).toEqual([source.internal_id]);
  });

  it('moves the objects of the sources to the target and keeps the source ids on it', async () => {
    await stixObjectMerge(testContext, ADMIN_USER, target.id, [source.id]);
    // The source is gone
    expect(await storeLoadById(testContext, ADMIN_USER, source.internal_id, ENTITY_TYPE_KILL_CHAIN_PHASE)).toBeUndefined();
    // Its objects now point to the target, and an object pointing to both keeps a single ref
    expect(await phaseIdsOf(onSource.id)).toEqual([target.internal_id]);
    expect(await phaseIdsOf(onBoth.id)).toEqual([target.internal_id]);
    // The target keeps its own names, and the standard id of the source so that a later import of it resolves to the target
    const merged = await storeLoadById<BasicStoreEntity>(testContext, ADMIN_USER, target.id, ENTITY_TYPE_KILL_CHAIN_PHASE);
    expect(merged).toMatchObject({ kill_chain_name: 'merge-chain-target', phase_name: 'command-and-control', x_opencti_order: 1 });
    expect(merged.x_opencti_stix_ids).toContain(source.standard_id);
    const resolvedFromSource = await storeLoadById<BasicStoreEntity>(testContext, ADMIN_USER, source.standard_id, ENTITY_TYPE_KILL_CHAIN_PHASE);
    expect(resolvedFromSource.internal_id).toBe(target.internal_id);
  });
});

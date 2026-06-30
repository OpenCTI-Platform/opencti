import { afterAll, describe, expect, it } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import { computeCollisionGroup, migrateEntityType } from '../../../../../src/modules/dataSanity/operations/caseSensitiveDuplicatedId';
import { ADMIN_USER, testContext } from '../../../../utils/testQuery';
import { elDelete, elIndex } from '../../../../../src/database/engine';
import { INDEX_STIX_DOMAIN_OBJECTS } from '../../../../../src/database/utils';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../../../../src/schema/stixDomainObject';
import { internalLoadById } from '../../../../../src/database/middleware-loader';

describe('Operation caseSensitiveDuplicatedId coverage', () => {
  // We create attack patterns directly in ES to bypass the normal upsert/deduplication
  // logic. The standard_id is pre-computed with different cases so they appear as distinct
  // entities in ES but will collide when generateStandardId re-computes them case-insensitively.
  const attackPatternIdCollision1 = uuidv4();
  const attackPatternIdCollision2 = uuidv4();
  const attackPatternNoCollision = uuidv4(); // non-colliding entity

  const baseDoc = {
    entity_type: ENTITY_TYPE_ATTACK_PATTERN,
    parent_types: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', ENTITY_TYPE_ATTACK_PATTERN],
    base_type: 'ENTITY',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  const doc1 = {
    ...baseDoc,
    internal_id: attackPatternIdCollision1,
    standard_id: `attack-pattern--${uuidv4()}`,
    name: 'Collision Test Pattern',
    x_mitre_id: 'T9999',
  };

  const doc2 = {
    ...baseDoc,
    internal_id: attackPatternIdCollision2,
    standard_id: `attack-pattern--${uuidv4()}`,
    name: 'Collision Test Pattern Duplicate',
    x_mitre_id: 't9999', // same mitre id, different case → will collide after case-insensitive re-computation
  };

  const doc3 = {
    ...baseDoc,
    internal_id: attackPatternNoCollision,
    standard_id: `attack-pattern--${uuidv4()}`,
    name: 'No Collision Pattern',
    x_mitre_id: 'T8888',
  };

  afterAll(async () => {
    // Cleanup: remove test documents from ES
    await elDelete(INDEX_STIX_DOMAIN_OBJECTS, attackPatternIdCollision1).catch(() => {});
    await elDelete(INDEX_STIX_DOMAIN_OBJECTS, attackPatternIdCollision2).catch(() => {});
    await elDelete(INDEX_STIX_DOMAIN_OBJECTS, attackPatternNoCollision).catch(() => {});
  });

  it('should find collision groups for attack patterns with case-differing x_mitre_id', async () => {
    // Insert directly into ES to bypass deduplication
    await elIndex(INDEX_STIX_DOMAIN_OBJECTS, doc1);
    await elIndex(INDEX_STIX_DOMAIN_OBJECTS, doc2);
    await elIndex(INDEX_STIX_DOMAIN_OBJECTS, doc3);

    const collisionGroups = await computeCollisionGroup(testContext, ENTITY_TYPE_ATTACK_PATTERN);

    // Find our specific collision group (there may be others from existing test data)
    const ourGroup = collisionGroups.find((group: any) =>
      group.some((entry: any) => entry.entity.internal_id === attackPatternIdCollision1),
    );

    expect(ourGroup).toBeDefined();
    expect(ourGroup!.length).toBe(2);

    const ids = ourGroup!.map((entry: any) => entry.entity.internal_id);
    expect(ids).toContain(attackPatternIdCollision1);
    expect(ids).toContain(attackPatternIdCollision2);
    expect(ids).not.toContain(attackPatternNoCollision);
  });

  it('should not flag entities with unique x_mitre_id as collisions', async () => {
    const collisionGroups = await computeCollisionGroup(testContext, ENTITY_TYPE_ATTACK_PATTERN);

    // doc3 with T8888 should NOT appear in any collision group
    const groupWithDoc3 = collisionGroups.find((group: any) =>
      group.some((entry: any) => entry.entity.internal_id === attackPatternNoCollision),
    );

    expect(groupWithDoc3).toBeUndefined();
  });

  it('should merge colliding attack patterns via migrateEntityType', async () => {
    // Ensure colliding docs are present (they were inserted in the first test)
    const beforeMerge1 = await internalLoadById(testContext, ADMIN_USER, attackPatternIdCollision1);
    const beforeMerge2 = await internalLoadById(testContext, ADMIN_USER, attackPatternIdCollision2);
    expect(beforeMerge1).toBeDefined();
    expect(beforeMerge2).toBeDefined();

    // Run the actual merge
    const result = await migrateEntityType(testContext, ENTITY_TYPE_ATTACK_PATTERN);

    // At least our collision group should have been merged
    expect(result.collisions).toBeGreaterThanOrEqual(1);
    expect(result.merged).toBeGreaterThanOrEqual(1);

    // After merge, only one of the two colliding entities should remain
    const afterMerge1 = await internalLoadById(testContext, ADMIN_USER, attackPatternIdCollision1);
    const afterMerge2 = await internalLoadById(testContext, ADMIN_USER, attackPatternIdCollision2);

    // One should be the surviving target, the other should be gone (merged into target)
    const survivors = [afterMerge1, afterMerge2].filter((e) => e !== undefined);
    expect(survivors.length).toBe(1);

    // The non-colliding entity should still exist untouched
    const afterMerge3 = await internalLoadById(testContext, ADMIN_USER, attackPatternNoCollision);
    expect(afterMerge3).toBeDefined();
  });
});

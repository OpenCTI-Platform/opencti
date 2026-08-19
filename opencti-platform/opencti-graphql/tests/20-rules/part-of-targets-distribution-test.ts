import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { addIntrusionSet } from '../../src/domain/intrusionSet';
import { addIdentity } from '../../src/domain/identity';
import { IdentityType } from '../../src/generated/graphql';
import { addOrganization } from '../../src/modules/organization/organization-domain';
import { stixCoreRelationshipsDistribution } from '../../src/domain/stixCoreRelationship';
import { createRelation, deleteElementById } from '../../src/database/middleware';
import { executionContext, SYSTEM_USER } from '../../src/utils/access';
import { RELATION_PART_OF, RELATION_TARGETS } from '../../src/schema/stixCoreRelationship';
import { ENTITY_TYPE_IDENTITY_SECTOR, ENTITY_TYPE_INTRUSION_SET } from '../../src/schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../src/modules/organization/organization-types';
import PartOfTargetsRule from '../../src/rules/part-of-targets/PartOfTargetsRule';
import { activateRule, disableRule } from '../utils/rule-utils';
import { testContext } from '../utils/testQuery';

// Regression test for https://github.com/OpenCTI-Platform/opencti/issues/11847
// Bug: the "targets" distribution used by the horizontal bar chart widget counted
// the number of inference explanations supporting a relationship instead of the
// number of distinct relationships, inflating the displayed values.
describe('Stix core relationships distribution - inferred relation explanations (#11847)', () => {
  const createdElements: { id: string; entity_type: string }[] = [];
  let intrusionSetId: string;
  let sectorId: string;

  beforeAll(async () => {
    // Build a minimal reproduction of the reported bug:
    // The IntrusionSet directly targets two organizations, both belonging (part-of) to
    // the same Sector. The "Targeting propagation via belonging" rule must infer a
    // SINGLE "IntrusionSet targets Sector" relationship, backed by TWO distinct
    // explanation paths (one per organization).
    const intrusionSet = await addIntrusionSet(testContext, SYSTEM_USER, { name: 'REGRESSION-11847 IntrusionSet' });
    intrusionSetId = intrusionSet.internal_id;
    createdElements.push({ id: intrusionSetId, entity_type: ENTITY_TYPE_INTRUSION_SET });

    const sector = await addIdentity(testContext, SYSTEM_USER, { name: 'REGRESSION-11847 Sector', type: IdentityType.Sector });
    sectorId = sector.internal_id;
    createdElements.push({ id: sectorId, entity_type: ENTITY_TYPE_IDENTITY_SECTOR });

    const orgA = await addOrganization(testContext, SYSTEM_USER, { name: 'REGRESSION-11847 OrgA' });
    createdElements.push({ id: orgA.internal_id, entity_type: ENTITY_TYPE_IDENTITY_ORGANIZATION });
    const orgB = await addOrganization(testContext, SYSTEM_USER, { name: 'REGRESSION-11847 OrgB' });
    createdElements.push({ id: orgB.internal_id, entity_type: ENTITY_TYPE_IDENTITY_ORGANIZATION });

    await createRelation(testContext, SYSTEM_USER, { fromId: intrusionSetId, toId: orgA.internal_id, relationship_type: RELATION_TARGETS });
    await createRelation(testContext, SYSTEM_USER, { fromId: intrusionSetId, toId: orgB.internal_id, relationship_type: RELATION_TARGETS });
    await createRelation(testContext, SYSTEM_USER, { fromId: orgA.internal_id, toId: sectorId, relationship_type: RELATION_PART_OF });
    await createRelation(testContext, SYSTEM_USER, { fromId: orgB.internal_id, toId: sectorId, relationship_type: RELATION_PART_OF });

    // Activating the rule triggers the rule manager and waits until inference is stable
    await activateRule(PartOfTargetsRule.id);
  }, 120000);

  afterAll(async () => {
    await disableRule(PartOfTargetsRule.id);
    for (let i = 0; i < createdElements.length; i += 1) {
      const { id, entity_type: entityType } = createdElements[i];
      await deleteElementById(testContext, SYSTEM_USER, id, entityType);
    }
  }, 120000);

  it('should count the inferred relation once, not once per explanation', async () => {
    const distributionContext = executionContext('testing', SYSTEM_USER);
    const distribution = await stixCoreRelationshipsDistribution(distributionContext, SYSTEM_USER, {
      field: 'internal_id',
      operation: 'count',
      fromId: [intrusionSetId],
      relationship_type: [RELATION_TARGETS],
      toTypes: [ENTITY_TYPE_IDENTITY_SECTOR],
    }) as { label: string; value: number; entity?: { id?: string } | null }[];

    const sectorBucket = distribution.find((d) => d.entity?.id === sectorId);
    expect(sectorBucket).toBeDefined();
    // The sector is the target of a SINGLE inferred "targets" relationship supported
    // by 2 explanations. It must be counted once (previously returned 2 due to the bug).
    expect(sectorBucket?.value).toBe(1);
  });
});

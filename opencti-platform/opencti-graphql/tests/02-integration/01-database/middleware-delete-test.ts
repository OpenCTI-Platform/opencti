import { describe, expect, it } from 'vitest';
import { deleteElementById } from '../../../src/database/middleware';
import { ADMIN_USER, TEST_ORGANIZATION, testContext } from '../../utils/testQuery';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_DECAY_RULE } from '../../../src/modules/decayRule/decayRule-types';
import { addDecayRule } from '../../../src/modules/decayRule/decayRule-domain';
import type { DecayRuleAddInput } from '../../../src/generated/graphql';
import { ENTITY_TYPE_GROUP } from '../../../src/schema/internalObject';

describe('Delete functional errors behaviors', async () => {
  it('should not be able to delete organization that has members', async () => {
    await expect(() => deleteElementById(testContext, ADMIN_USER, TEST_ORGANIZATION.id, ENTITY_TYPE_IDENTITY_ORGANIZATION))
      .rejects.toThrowError('Cannot delete an organization that has members.');
  });
  it.skip('should not be able to delete individual associated to user', async () => {
    const individualUserId = 'identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91'; // admin individual
    await expect(() => deleteElementById(testContext, ADMIN_USER, individualUserId, ENTITY_TYPE_IDENTITY_INDIVIDUAL))
      .rejects.toThrowError('Cannot delete an individual corresponding to a user');
  });

  it('should not be able to delete another target than the entity type', async () => {
    const decayRule: DecayRuleAddInput = {
      active: true,
      decay_lifetime: 360,
      decay_pound: 1,
      decay_revoke_score: 10,
      name: 'Decay for middleware delete test',
      order: 12
    };
    const decayRuleCreated = await addDecayRule(testContext, ADMIN_USER, decayRule);

    await expect(() => deleteElementById(testContext, ADMIN_USER, decayRuleCreated.id, ENTITY_TYPE_GROUP))
      .rejects.toThrowError('Cant find element for deletion');

    // But delete with the right entity type is fine:
    const deleted = await deleteElementById(testContext, ADMIN_USER, decayRuleCreated.id, ENTITY_TYPE_DECAY_RULE);
    expect(deleted.id).toBe(decayRuleCreated.id);
    expect(deleted.entity_type).toBe(ENTITY_TYPE_DECAY_RULE);
  });
});

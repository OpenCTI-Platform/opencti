import { describe, expect, it } from 'vitest';
import { deleteElementById } from '../../../src/database/middleware';
import { ADMIN_USER, TEST_ORGANIZATION, testContext } from '../../utils/testQuery';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import { ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_IDENTITY_INDIVIDUAL } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_DECAY_RULE } from '../../../src/modules/decayRule/decayRule-types';
import { addDecayRule } from '../../../src/modules/decayRule/decayRule-domain';
import { type DecayRuleAddInput, type ReportAddInput, type RetentionRuleAddInput, RetentionRuleScope } from '../../../src/generated/graphql';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_RETENTION_RULE } from '../../../src/schema/internalObject';
import { addReport } from '../../../src/domain/report';
import { utcDate } from '../../../src/utils/format';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CYBER_OBSERVABLE, ENTITY_TYPE_CONTAINER } from '../../../src/schema/general';
import { createRetentionRule } from '../../../src/domain/retentionRule';

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
      .rejects.toThrowError('Already deleted elements');

    // But delete with the right entity type is fine:
    const deleted = await deleteElementById(testContext, ADMIN_USER, decayRuleCreated.id, ENTITY_TYPE_DECAY_RULE);
    expect(deleted.id).toBe(decayRuleCreated.id);
    expect(deleted.entity_type).toBe(ENTITY_TYPE_DECAY_RULE);
  });

  it('should be able to delete a report using Stix Core Object parent type', async () => {
    const reportAddData: ReportAddInput = {
      name: 'Report for middleware-delete-test',
      published: utcDate()
    };
    const reportToBeDeleted = await addReport(testContext, ADMIN_USER, reportAddData);
    const deleted = await deleteElementById(testContext, ADMIN_USER, reportToBeDeleted.id, ABSTRACT_STIX_CORE_OBJECT);

    expect(deleted.id).toBe(reportToBeDeleted.id);
    expect(deleted.entity_type).toBe(ENTITY_TYPE_CONTAINER_REPORT);
  });

  it('should be able to delete a report using container parent type', async () => {
    const reportAddData: ReportAddInput = {
      name: 'Report2 for middleware-delete-test',
      published: utcDate()
    };
    const reportToBeDeleted = await addReport(testContext, ADMIN_USER, reportAddData);
    const deleted = await deleteElementById(testContext, ADMIN_USER, reportToBeDeleted.id, ENTITY_TYPE_CONTAINER);

    expect(deleted.id).toBe(reportToBeDeleted.id);
    expect(deleted.entity_type).toBe(ENTITY_TYPE_CONTAINER_REPORT);
  });

  it('should not be able to delete a report using Observable parent type', async () => {
    const reportAddData: ReportAddInput = {
      name: 'Report3 for middleware-delete-test',
      published: utcDate()
    };
    const reportToBeDeleted = await addReport(testContext, ADMIN_USER, reportAddData);
    await expect(() => deleteElementById(testContext, ADMIN_USER, reportToBeDeleted.id, ABSTRACT_STIX_CYBER_OBSERVABLE))
      .rejects.toThrowError('Already deleted elements');

    // But delete with the right entity type is fine:
    const deleted = await deleteElementById(testContext, ADMIN_USER, reportToBeDeleted.id, ENTITY_TYPE_CONTAINER_REPORT);
    expect(deleted.id).toBe(reportToBeDeleted.id);
    expect(deleted.entity_type).toBe(ENTITY_TYPE_CONTAINER_REPORT);
  });

  it('should be able to delete an entity without parent type', async () => {
    const retentionRule: RetentionRuleAddInput = {
      max_retention: 0,
      name: 'Retention rule for middleware-delete-test',
      scope: RetentionRuleScope.File
    };
    const retentionRuleCreated = await createRetentionRule(testContext, ADMIN_USER, retentionRule);
    const deleted = await deleteElementById(testContext, ADMIN_USER, retentionRuleCreated.id, ENTITY_TYPE_RETENTION_RULE);

    expect(deleted.id).toBe(retentionRuleCreated.id);
    expect(deleted.entity_type).toBe(ENTITY_TYPE_RETENTION_RULE);
  });
});

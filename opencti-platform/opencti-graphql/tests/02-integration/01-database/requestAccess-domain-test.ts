import { describe, it, expect } from 'vitest';
import { findUsersThatCanShareWithOrganizations } from '../../../src/modules/requestAccess/requestAccess-domain';
import { ADMIN_USER, TEST_ORGANIZATION, testContext, USER_EDITOR } from '../../utils/testQuery';
import { getOrganizationEntity } from '../../utils/domainQueryHelper';
import { findByType as findEntitySettingsByType } from '../../../src/modules/entitySetting/entitySetting-domain';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../../src/modules/case/case-rfi/case-rfi-types';
import { findTemplateById } from '../../../src/domain/status';

describe('Request access domain  - initialized status', async () => {
  it('should initial data be created', async () => {
    const rfiEntitySettings = await findEntitySettingsByType(testContext, ADMIN_USER, ENTITY_TYPE_CONTAINER_CASE_RFI);
    const approvedStatusId = rfiEntitySettings.request_access_workflow?.approved_workflow_id;
    expect(approvedStatusId).toBeDefined();
    expect(approvedStatusId?.length, 'The status id must be a string not empty').toBeGreaterThan(1);
    if (approvedStatusId) {
      const statusData = await findTemplateById(testContext, ADMIN_USER, approvedStatusId);
      expect(statusData.name).toBe('APPROVED');
    }

    const declinedStatusId = rfiEntitySettings.request_access_workflow?.declined_workflow_id;
    expect(declinedStatusId).toBeDefined();
    expect(declinedStatusId?.length, 'The status id must be a string not empty').toBeGreaterThan(1);
    if (declinedStatusId) {
      const statusData = await findTemplateById(testContext, ADMIN_USER, declinedStatusId);
      expect(statusData.name).toBe('DECLINED');
    }
  });
});

describe('Request access domain level test coverage', async () => {
  it.todo('should find users that can share knowledge with an org', async () => {
    const testOrgEntity = await getOrganizationEntity(TEST_ORGANIZATION);
    const result = await findUsersThatCanShareWithOrganizations(testContext, ADMIN_USER, [testOrgEntity.id]);
    expect(result[0].user_email).toBe(USER_EDITOR.email);
  });
});

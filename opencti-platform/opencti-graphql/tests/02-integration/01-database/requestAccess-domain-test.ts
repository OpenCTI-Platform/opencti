import { describe, it, expect } from 'vitest';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { findByType as findEntitySettingsByType } from '../../../src/modules/entitySetting/entitySetting-domain';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../../src/modules/case/case-rfi/case-rfi-types';
import { findById as findStatusById, findTemplateById } from '../../../src/domain/status';

describe('Request access domain  - initialized status', async () => {
  it('should initial data be created', async () => {
    const rfiEntitySettings = await findEntitySettingsByType(testContext, ADMIN_USER, ENTITY_TYPE_CONTAINER_CASE_RFI);
    const approvedStatusId = rfiEntitySettings.request_access_workflow?.approved_workflow_id;
    expect(approvedStatusId).toBeDefined();
    expect(approvedStatusId?.length, 'The status id must be a string not empty').toBeGreaterThan(1);
    if (approvedStatusId) {
      const statusInRfi = await findStatusById(testContext, ADMIN_USER, approvedStatusId);
      const statusData = await findTemplateById(testContext, ADMIN_USER, statusInRfi.template_id);
      expect(statusData.name).toBe('APPROVED');
    }

    const declinedStatusId = rfiEntitySettings.request_access_workflow?.declined_workflow_id;
    expect(declinedStatusId).toBeDefined();
    expect(declinedStatusId?.length, 'The status id must be a string not empty').toBeGreaterThan(1);
    if (declinedStatusId) {
      const statusInRfi = await findStatusById(testContext, ADMIN_USER, declinedStatusId);
      const statusData = await findTemplateById(testContext, ADMIN_USER, statusInRfi.template_id);
      expect(statusData.name).toBe('DECLINED');
    }
  });
});

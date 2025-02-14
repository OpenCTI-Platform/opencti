import { describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { findByType as findEntitySettingsByType } from '../../../src/modules/entitySetting/entitySetting-domain';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../../src/modules/case/case-rfi/case-rfi-types';
import {
  createStatus,
  createStatusTemplate,
  findAll as findAllStatuses,
  findAllTemplatesByStatusScope,
  findById as findStatusById,
  findTemplateById
} from '../../../src/domain/status';
import {
  FilterMode,
  OrderingMode,
  type QueryStatusesArgs,
  type QueryStatusTemplatesByStatusScopeArgs,
  StatusOrdering,
  StatusScope,
  type StatusTemplate,
} from '../../../src/generated/graphql';
import type { BasicStoreEntity } from '../../../src/types/store';
import { resetCacheForEntity } from '../../../src/database/cache';
import { ENTITY_TYPE_STATUS } from '../../../src/schema/internalObject';

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

  let statusTemplateGlobalRfi: BasicStoreEntity;
  let statusTemplateRequestAccess: BasicStoreEntity;

  it('should get request access scope status', async () => {
    statusTemplateGlobalRfi = await createStatusTemplate(testContext, ADMIN_USER, { name: 'GLOBAL_RFI', color: '#b83f13' });
    statusTemplateRequestAccess = await createStatusTemplate(testContext, ADMIN_USER, { name: 'REQUEST_ACCESS_SCOPE', color: '#b83f13' });
    await createStatus(
      testContext,
      ADMIN_USER,
      ENTITY_TYPE_CONTAINER_CASE_RFI,
      { template_id: statusTemplateGlobalRfi.id, order: 666, scope: StatusScope.Global }
    );

    await createStatus(
      testContext,
      ADMIN_USER,
      ENTITY_TYPE_CONTAINER_CASE_RFI,
      { template_id: statusTemplateRequestAccess.id, order: 111, scope: StatusScope.RequestAccess }
    );

    const args: QueryStatusesArgs = {
      first: 100,
      filters: {
        mode: FilterMode.And,
        filterGroups: [],
        filters: [
          { key: ['type'], values: ['Case-Rfi'] },
          { key: ['scope'], values: [StatusScope.RequestAccess] },
        ],
      },
      orderBy: StatusOrdering.Order,
      orderMode: OrderingMode.Asc,
    };

    resetCacheForEntity(ENTITY_TYPE_STATUS);

    const result = await findAllStatuses(testContext, ADMIN_USER, args);
    expect(result.edges.some((status) => status.node.template_id === statusTemplateRequestAccess.id)).toBeTruthy();
    expect(result.edges.some((status) => status.node.template_id === statusTemplateGlobalRfi.id)).toBeFalsy();
  });

  it('should get global status when scope is Global', async () => {
    const args: QueryStatusesArgs = {
      first: 100,
      filters: {
        mode: FilterMode.And,
        filterGroups: [],
        filters: [
          { key: ['type'], values: ['Case-Rfi'] },
          { key: ['scope'], values: [StatusScope.Global] },
        ],
      },
      orderBy: StatusOrdering.Order,
      orderMode: OrderingMode.Asc,
    };
    const result = await findAllStatuses(testContext, ADMIN_USER, args);
    expect(result.edges.some((status) => status.node.template_id === statusTemplateRequestAccess.id)).toBeFalsy();
    expect(result.edges.some((status) => status.node.template_id === statusTemplateGlobalRfi.id)).toBeTruthy();
  });

  it('should get all status template by GLOBAL scope', async () => {
    const args:QueryStatusTemplatesByStatusScopeArgs = {
      scope: StatusScope.Global
    };
    const globalTemplates: StatusTemplate[] = await findAllTemplatesByStatusScope(testContext, ADMIN_USER, args);
    expect(globalTemplates?.some((template) => template?.name === 'GLOBAL_RFI')).toBeTruthy();
    expect(globalTemplates?.some((template) => template?.name === 'REQUEST_ACCESS_SCOPE')).toBeFalsy();
  });

  it('should get all status template by REQUEST_ACCESS scope', async () => {
    const args:QueryStatusTemplatesByStatusScopeArgs = {
      scope: StatusScope.RequestAccess
    };
    const requestAccessTemplates: StatusTemplate[] = await findAllTemplatesByStatusScope(testContext, ADMIN_USER, args);
    expect(requestAccessTemplates?.some((template) => template?.name === 'GLOBAL_RFI')).toBeFalsy();
    expect(requestAccessTemplates?.some((template) => template?.name === 'REQUEST_ACCESS_SCOPE')).toBeTruthy();
  });
});

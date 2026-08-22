import { describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { createStatus, createStatusTemplate, findStatusByTypeScopeAndTemplateName, resolveSyncedWorkflowId } from '../../../src/domain/status';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../../src/modules/case/case-rfi/case-rfi-types';
import { StatusScope } from '../../../src/generated/graphql';
import { resetCacheForEntity } from '../../../src/database/cache';
import { ENTITY_TYPE_STATUS, ENTITY_TYPE_STATUS_TEMPLATE } from '../../../src/schema/internalObject';

describe('Status domain - sync workflow status matching', () => {
  const templateName = `SYNC_MATCH_TEMPLATE_${Date.now()}`;
  let statusId: string;

  it('should create a status template and a status for matching', async () => {
    const template = await createStatusTemplate(testContext, ADMIN_USER, { name: templateName, color: '#123456' });
    const status = await createStatus(
      testContext,
      ADMIN_USER,
      ENTITY_TYPE_CONTAINER_CASE_RFI,
      { template_id: template.id, order: 555, scope: StatusScope.Global },
    );
    statusId = status.id;
    resetCacheForEntity(ENTITY_TYPE_STATUS);
    resetCacheForEntity(ENTITY_TYPE_STATUS_TEMPLATE);
  });

  it('should find the status by matching type, scope and template name', async () => {
    const found = await findStatusByTypeScopeAndTemplateName(
      testContext,
      ADMIN_USER,
      ENTITY_TYPE_CONTAINER_CASE_RFI,
      StatusScope.Global,
      templateName,
    );
    expect(found?.id).toBe(statusId);
  });

  it('should not find a status for an unknown template name', async () => {
    const found = await findStatusByTypeScopeAndTemplateName(
      testContext,
      ADMIN_USER,
      ENTITY_TYPE_CONTAINER_CASE_RFI,
      StatusScope.Global,
      'UNKNOWN_TEMPLATE_NAME',
    );
    expect(found).toBeUndefined();
  });

  it('should not find a status when the scope does not match', async () => {
    const found = await findStatusByTypeScopeAndTemplateName(
      testContext,
      ADMIN_USER,
      ENTITY_TYPE_CONTAINER_CASE_RFI,
      StatusScope.RequestAccess,
      templateName,
    );
    expect(found).toBeUndefined();
  });

  it('should not find a status when the type does not match', async () => {
    const found = await findStatusByTypeScopeAndTemplateName(
      testContext,
      ADMIN_USER,
      'Report',
      StatusScope.Global,
      templateName,
    );
    expect(found).toBeUndefined();
  });

  it('should resolve the local workflow id for a matching remote status', async () => {
    const localWorkflowId = await resolveSyncedWorkflowId(
      testContext,
      ADMIN_USER,
      ENTITY_TYPE_CONTAINER_CASE_RFI,
      StatusScope.Global,
      templateName,
    );
    expect(localWorkflowId).toBe(statusId);
  });

  it('should resolve undefined when there is no matching local status', async () => {
    const localWorkflowId = await resolveSyncedWorkflowId(
      testContext,
      ADMIN_USER,
      ENTITY_TYPE_CONTAINER_CASE_RFI,
      StatusScope.Global,
      'UNKNOWN_TEMPLATE_NAME',
    );
    expect(localWorkflowId).toBeUndefined();
  });

  it('should resolve undefined when the remote template name is missing', async () => {
    const localWorkflowId = await resolveSyncedWorkflowId(
      testContext,
      ADMIN_USER,
      ENTITY_TYPE_CONTAINER_CASE_RFI,
      StatusScope.Global,
      undefined,
    );
    expect(localWorkflowId).toBeUndefined();
  });
});

import { beforeAll, afterAll, describe, expect, it, vi } from 'vitest';
import { ADMIN_USER, getGroupIdByName, getOrganizationIdByName, GREEN_GROUP, PLATFORM_ORGANIZATION, TEST_ORGANIZATION, testContext } from '../../utils/testQuery';
import { entitySettingEditField, findByType as findEntitySettingsByType } from '../../../src/modules/entitySetting/entitySetting-domain';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../../src/modules/case/case-rfi/case-rfi-types';
import { createStatus, createStatusTemplate, findStatusPaginated, findAllTemplatesByStatusScope, findById as findStatusById, findTemplateById } from '../../../src/domain/status';
import {
  type EditInput,
  FilterMode,
  OrderingMode,
  type QueryStatusesArgs,
  type QueryStatusTemplatesByStatusScopeArgs,
  type RequestAccessConfigureInput,
  StatusOrdering,
  StatusScope,
  type StatusTemplate,
} from '../../../src/generated/graphql';
import type { BasicStoreCommon, BasicStoreEntity, BasicWorkflowStatus, BasicWorkflowTemplateEntity } from '../../../src/types/store';
import { logApp } from '../../../src/config/conf';
import { resetCacheForEntity } from '../../../src/database/cache';
import { ENTITY_TYPE_STATUS } from '../../../src/schema/internalObject';
import {
  addRequestAccess,
  approveRequestAccess,
  computeAuthorizedMembersForRequestAccess,
  configureRequestAccess,
  declineRequestAccess,
  getRfiEntitySettings,
} from '../../../src/modules/requestAccess/requestAccess-domain';
import { executionContext, MEMBER_ACCESS_RIGHT_ADMIN, MEMBER_ACCESS_RIGHT_EDIT } from '../../../src/utils/access';
import type { BasicStoreEntityEntitySetting, RequestAccessFlow } from '../../../src/modules/entitySetting/entitySetting-types';
import { unSetOrganization, setOrganization } from '../../utils/testQueryHelper';
import { OPENCTI_ADMIN_UUID } from '../../../src/schema/general';
import { verifyRequestAccessEnabled } from '../../../src/modules/requestAccess/requestAccessUtils';
import type { BasicStoreSettings } from '../../../src/types/settings';
import { getFakeAuthUser, getGroupEntity } from '../../utils/domainQueryHelper';
import type { Group } from '../../../src/types/group';
import * as entrepriseEdition from '../../../src/enterprise-edition/ee';

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
    statusTemplateGlobalRfi = await createStatusTemplate(testContext, ADMIN_USER, {
      name: 'GLOBAL_RFI',
      color: '#b83f13',
    });
    statusTemplateRequestAccess = await createStatusTemplate(testContext, ADMIN_USER, {
      name: 'REQUEST_ACCESS_SCOPE',
      color: '#b83f13',
    });
    await createStatus(
      testContext,
      ADMIN_USER,
      ENTITY_TYPE_CONTAINER_CASE_RFI,
      { template_id: statusTemplateGlobalRfi.id, order: 666, scope: StatusScope.Global },
    );

    await createStatus(
      testContext,
      ADMIN_USER,
      ENTITY_TYPE_CONTAINER_CASE_RFI,
      { template_id: statusTemplateRequestAccess.id, order: 111, scope: StatusScope.RequestAccess },
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

    const result = await findStatusPaginated(testContext, ADMIN_USER, args);
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
    const result = await findStatusPaginated(testContext, ADMIN_USER, args);
    expect(result.edges.some((status) => status.node.template_id === statusTemplateRequestAccess.id)).toBeFalsy();
    expect(result.edges.some((status) => status.node.template_id === statusTemplateGlobalRfi.id)).toBeTruthy();
  });

  it('should get all status template by GLOBAL scope', async () => {
    resetCacheForEntity(ENTITY_TYPE_STATUS);
    const args: QueryStatusTemplatesByStatusScopeArgs = {
      scope: StatusScope.Global,
    };
    const globalTemplates: StatusTemplate[] = await findAllTemplatesByStatusScope(testContext, ADMIN_USER, args);
    logApp.info('[TEST] globalTemplates', { globalTemplates });
    expect(globalTemplates?.some((template) => template?.name === 'GLOBAL_RFI')).toBeTruthy();
    expect(globalTemplates?.some((template) => template?.name === 'REQUEST_ACCESS_SCOPE')).toBeFalsy();
  });

  it('should get all status template by REQUEST_ACCESS scope', async () => {
    resetCacheForEntity(ENTITY_TYPE_STATUS);
    const args: QueryStatusTemplatesByStatusScopeArgs = {
      scope: StatusScope.RequestAccess,
    };
    const requestAccessTemplates: StatusTemplate[] = await findAllTemplatesByStatusScope(testContext, ADMIN_USER, args);
    logApp.info('[TEST] requestAccessTemplates', { requestAccessTemplates });
    expect(requestAccessTemplates?.some((template) => template?.name === 'GLOBAL_RFI')).toBeFalsy();
    expect(requestAccessTemplates?.some((template) => template?.name === 'REQUEST_ACCESS_SCOPE')).toBeTruthy();
  });
});

describe('Request access domain  - compute RFI retricted members', async () => {
  let greenGroupId: string;
  let rfiEntitySettings: BasicStoreEntityEntitySetting;
  let platformOrganizationId: string;
  let testOrganizationId: string;

  beforeAll(async () => {
    // Activate EE for this test
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
    await setOrganization(PLATFORM_ORGANIZATION);
    platformOrganizationId = await getOrganizationIdByName(PLATFORM_ORGANIZATION.name);
    testOrganizationId = await getOrganizationIdByName(TEST_ORGANIZATION.name);
  });

  afterAll(async () => {
    // Deactivate EE at the end of this test - back to CE
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockRejectedValue('Enterprise edition is not enabled');
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(false);
    await unSetOrganization();
  });

  it('should configure request access settings', async () => {
    greenGroupId = await getGroupIdByName(GREEN_GROUP.name);
    rfiEntitySettings = await getRfiEntitySettings(testContext, ADMIN_USER);
    logApp.info('[TEST RA] rfiEntitySettings BEFORE', { rfiEntitySettings });
    const raConfig = { ...rfiEntitySettings.request_access_workflow };
    raConfig.approval_admin = [greenGroupId];

    const editInput: EditInput[] = [
      { key: 'request_access_workflow', value: [raConfig] },
    ];
    await entitySettingEditField(testContext, ADMIN_USER, rfiEntitySettings.id, editInput);

    rfiEntitySettings = await getRfiEntitySettings(testContext, ADMIN_USER);
    logApp.info('[TEST RA] rfiEntitySettings AFTER', { rfiEntitySettings });
  });

  it('should knowledge sharing request on entity with restricted members be refused', async () => {
    const someEntity: Partial<BasicStoreCommon> = {
      restricted_members: [
        {
          id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
          access_right: 'admin',
        },
        {
          id: '55ec0c6a-13ce-5e39-b486-354fe4a7084f',
          access_right: 'view',
        },
      ],
      granted: [PLATFORM_ORGANIZATION.id],
    };

    await expect(async () => {
      await computeAuthorizedMembersForRequestAccess(testContext, ADMIN_USER, someEntity as BasicStoreCommon);
    }).rejects.toThrowError('This entity is restricted with authorized member and cannot be requested for sharing.');
  });

  it('should knowledge sharing request on entity without any organisation sharing use platform organization', async () => {
    // No granted part
    const someEntity: Partial<BasicStoreCommon> = {};

    const authorizedMembers = await computeAuthorizedMembersForRequestAccess(testContext, ADMIN_USER, someEntity as BasicStoreCommon);
    expect(authorizedMembers.find((member) => member.access_right === MEMBER_ACCESS_RIGHT_ADMIN)).toStrictEqual({
      id: OPENCTI_ADMIN_UUID,
      access_right: MEMBER_ACCESS_RIGHT_ADMIN,
    });
    expect(authorizedMembers.find((member) => member.access_right === MEMBER_ACCESS_RIGHT_EDIT)).toStrictEqual({
      id: platformOrganizationId,
      access_right: MEMBER_ACCESS_RIGHT_EDIT,
      groups_restriction_ids: [greenGroupId],
    });
  });

  it('should knowledge sharing request on entity with organisation sharing use it', async () => {
    // No granted part
    const someEntity: Partial<BasicStoreCommon> = {
      granted: [testOrganizationId],
    };

    const authorizedMembers = await computeAuthorizedMembersForRequestAccess(testContext, ADMIN_USER, someEntity as BasicStoreCommon);
    expect(authorizedMembers.find((member) => member.access_right === MEMBER_ACCESS_RIGHT_ADMIN)).toStrictEqual({
      id: OPENCTI_ADMIN_UUID,
      access_right: MEMBER_ACCESS_RIGHT_ADMIN,
    });
    expect(authorizedMembers.find((member) => member.access_right === MEMBER_ACCESS_RIGHT_EDIT)).toStrictEqual({
      id: testOrganizationId,
      access_right: MEMBER_ACCESS_RIGHT_EDIT,
      groups_restriction_ids: [greenGroupId],
    });
  });

  it('should knowledge sharing request on entity with several organisation sharing use them', async () => {
    // No granted part
    const someEntity: Partial<BasicStoreCommon> = {
      granted: [testOrganizationId, platformOrganizationId],
    };

    const authorizedMembers = await computeAuthorizedMembersForRequestAccess(testContext, ADMIN_USER, someEntity as BasicStoreCommon);
    expect(authorizedMembers.find((member) => member.access_right === MEMBER_ACCESS_RIGHT_ADMIN)).toStrictEqual({
      id: OPENCTI_ADMIN_UUID,
      access_right: MEMBER_ACCESS_RIGHT_ADMIN,
    });
    expect(authorizedMembers.filter((member) => member.access_right === MEMBER_ACCESS_RIGHT_EDIT).length).toBe(2);
    expect(authorizedMembers.find((member) => member.access_right === MEMBER_ACCESS_RIGHT_EDIT && member.id === testOrganizationId)).toStrictEqual({
      id: testOrganizationId,
      access_right: MEMBER_ACCESS_RIGHT_EDIT,
      groups_restriction_ids: [greenGroupId],
    });

    expect(authorizedMembers.find((member) => member.access_right === MEMBER_ACCESS_RIGHT_EDIT && member.id === platformOrganizationId)).toStrictEqual({
      id: platformOrganizationId,
      access_right: MEMBER_ACCESS_RIGHT_EDIT,
      groups_restriction_ids: [greenGroupId],
    });
  });
});

describe('Request access domain  - conditions for request access activated', async () => {
  it('should CE be forbidden to use request access', async () => {
    const settings: Partial<BasicStoreSettings> = {
      valid_enterprise_edition: false,
      platform_organization: TEST_ORGANIZATION.id,
    };

    const rfiSettings: Partial<BasicStoreEntityEntitySetting> = {
      request_access_workflow: {
        approval_admin: [GREEN_GROUP.id],
        approved_workflow_id: '1234',
        declined_workflow_id: '5678',
      },
    };

    const isRequestAccessEnabled = verifyRequestAccessEnabled(settings as BasicStoreSettings, rfiSettings as BasicStoreEntityEntitySetting);
    expect(isRequestAccessEnabled.enabled).toBeFalsy();
    expect(isRequestAccessEnabled.message).toBe('Enterprise edition must be enabled.');
  });

  it('should request access be disabled when there is no platform organization', async () => {
    const settings: Partial<BasicStoreSettings> = {
      valid_enterprise_edition: true,
    };

    const rfiSettings: Partial<BasicStoreEntityEntitySetting> = {
      request_access_workflow: {
        approval_admin: [GREEN_GROUP.id],
        approved_workflow_id: '1234',
        declined_workflow_id: '5678',
      },
    };

    const isRequestAccessEnabled = verifyRequestAccessEnabled(settings as BasicStoreSettings, rfiSettings as BasicStoreEntityEntitySetting);
    expect(isRequestAccessEnabled.enabled).toBeFalsy();
    expect(isRequestAccessEnabled.message).toBe('Platform organization must be setup.');
  });

  it('should request access be disabled when admin group is not setup', async () => {
    const settings: Partial<BasicStoreSettings> = {
      valid_enterprise_edition: true,
      platform_organization: TEST_ORGANIZATION.id,
    };

    const rfiSettings: Partial<BasicStoreEntityEntitySetting> = {
      request_access_workflow: {
        approval_admin: [],
        approved_workflow_id: '1234',
        declined_workflow_id: '5678',
      },
    };

    const isRequestAccessEnabled = verifyRequestAccessEnabled(settings as BasicStoreSettings, rfiSettings as BasicStoreEntityEntitySetting);
    expect(isRequestAccessEnabled.enabled).toBeFalsy();
    expect(isRequestAccessEnabled.message).toBe('At least one approval administrator must be configured in entity settings.');
  });

  it('should request access be disabled when approved_workflow_id or declined_workflow_id is not setup', async () => {
    const settings: Partial<BasicStoreSettings> = {
      valid_enterprise_edition: true,
      platform_organization: TEST_ORGANIZATION.id,
    };

    const rfiSettings: Partial<BasicStoreEntityEntitySetting> = {
      request_access_workflow: {
        approval_admin: [GREEN_GROUP.id],
      },
    };

    const isRequestAccessEnabled = verifyRequestAccessEnabled(settings as BasicStoreSettings, rfiSettings as BasicStoreEntityEntitySetting);
    expect(isRequestAccessEnabled.enabled).toBeFalsy();
    expect(isRequestAccessEnabled.message).toBe('RFI status for decline and approval must be configured in entity settings.');
  });

  it('should request access be enabled when everything is configured', async () => {
    const settings: Partial<BasicStoreSettings> = {
      valid_enterprise_edition: true,
      platform_organization: TEST_ORGANIZATION.id,
    };

    const rfiSettings: Partial<BasicStoreEntityEntitySetting> = {
      request_access_workflow: {
        approval_admin: [GREEN_GROUP.id],
        approved_workflow_id: '1234',
        declined_workflow_id: '5678',
      },
    };

    const isRequestAccessEnabled = verifyRequestAccessEnabled(settings as BasicStoreSettings, rfiSettings as BasicStoreEntityEntitySetting);
    expect(isRequestAccessEnabled.enabled).toBeTruthy();
  });
});

describe('Request access domain  - draft', async () => {
  it('create request access RFI should be disabled from draft context', async () => {
    const fakeUser = getFakeAuthUser('RequestAccessInDraft');
    const testContextInDraft = executionContext('testing', fakeUser, 'fake-draft-id');
    const input = { request_access_entities: [], request_access_members: [] };
    await expect(() => addRequestAccess(testContextInDraft, fakeUser, input)).rejects.toThrowError('Request access is not available in draft mode');
  });

  it('approve request access should be disabled from draft context', async () => {
    const fakeUser = getFakeAuthUser('RequestAccessInDraft');
    const testContextInDraft = executionContext('testing', fakeUser, 'fake-draft-id');
    await expect(() => approveRequestAccess(testContextInDraft, fakeUser, 'fake-rfi-id')).rejects.toThrowError('Request access is not available in draft mode');
  });

  it('decline request access should be disabled from draft context', async () => {
    const fakeUser = getFakeAuthUser('RequestAccessInDraft');
    const testContextInDraft = executionContext('testing', fakeUser, 'fake-draft-id');
    await expect(() => declineRequestAccess(testContextInDraft, fakeUser, 'fake-rfi-id')).rejects.toThrowError('Request access is not available in draft mode');
  });
});

describe('Request access domain  - configuration edition', async () => {
  let statusTemplateRequestAccess: BasicWorkflowTemplateEntity;
  let statusRequestAccess: BasicWorkflowStatus;
  let greenGroup: Group;
  let initialConfig: RequestAccessFlow | undefined;
  let rfiEntitySettings: BasicStoreEntityEntitySetting;

  beforeAll(async () => {
    rfiEntitySettings = await getRfiEntitySettings(testContext, ADMIN_USER);
    initialConfig = rfiEntitySettings.request_access_workflow;

    statusTemplateRequestAccess = await createStatusTemplate(testContext, ADMIN_USER, { name: 'REQUEST_ACCESS_CONFIG', color: '#8c13b8' });
    statusRequestAccess = await createStatus(
      testContext,
      ADMIN_USER,
      ENTITY_TYPE_CONTAINER_CASE_RFI,
      { template_id: statusTemplateRequestAccess.id, order: 3, scope: StatusScope.RequestAccess },
    );

    greenGroup = await getGroupEntity(GREEN_GROUP);
  });

  afterAll(async () => {
    const editInput: EditInput[] = [
      { key: 'request_access_workflow', value: [initialConfig] },
    ];
    await entitySettingEditField(testContext, ADMIN_USER, rfiEntitySettings?.id, editInput);
  });

  it('should disabling approval_admin in request access be allowed', async () => {
    const input: RequestAccessConfigureInput = {
      approval_admin: undefined,
      approved_status_id: statusTemplateRequestAccess.id,
      declined_status_id: statusTemplateRequestAccess.id,
    };

    const configuration = await configureRequestAccess(testContext, ADMIN_USER, input);

    // Should not throw exceptions and
    expect(configuration.approval_admin).toStrictEqual([]);
  });

  it('should disabling approved_status_id in request access be allowed', async () => {
    const input: RequestAccessConfigureInput = {
      approval_admin: [greenGroup.id],
      approved_status_id: undefined,
      declined_status_id: statusTemplateRequestAccess.id,
    };

    const configuration = await configureRequestAccess(testContext, ADMIN_USER, input);

    // Should not throw exceptions and
    expect(configuration.approval_admin).toStrictEqual([{ id: greenGroup.id, name: GREEN_GROUP.name }]);
    expect(configuration.declined_status?.id).toStrictEqual(statusRequestAccess.id);
  });

  it('should disabling approved_status_id in request access be allowed', async () => {
    const input: RequestAccessConfigureInput = {
      approval_admin: [greenGroup.id],
      approved_status_id: statusTemplateRequestAccess.id,
      declined_status_id: undefined,
    };

    const configuration = await configureRequestAccess(testContext, ADMIN_USER, input);

    // Should not throw exceptions and
    expect(configuration.approval_admin).toStrictEqual([{ id: greenGroup.id, name: GREEN_GROUP.name }]);
    expect(configuration.approved_status?.id).toStrictEqual(statusRequestAccess.id);
  });
});

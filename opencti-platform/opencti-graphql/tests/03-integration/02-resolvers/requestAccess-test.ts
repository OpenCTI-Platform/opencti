import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import gql from 'graphql-tag';
import {
  ADMIN_USER,
  AMBER_GROUP,
  getAuthUser,
  getGroupIdByName,
  GREEN_GROUP,
  PLATFORM_ORGANIZATION,
  TEST_ORGANIZATION,
  testContext,
  USER_DISINFORMATION_ANALYST,
  USER_EDITOR,
} from '../../utils/testQuery';
import { addCaseRfi, findById as findRFIById } from '../../../src/modules/case/case-rfi/case-rfi-domain';
import { unSetOrganization, setOrganization, queryAsAdmin, queryAsAdminWithSuccess, queryAsUser, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { getOrganizationEntity } from '../../utils/domainQueryHelper';
import {
  ActionStatus,
  addRequestAccess,
  findWorkflowStatusByTemplateId,
  getRfiEntitySettings,
  type RequestAccessAction,
} from '../../../src/modules/requestAccess/requestAccess-domain';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../../src/modules/case/case-rfi/case-rfi-types';
import { createStatusTemplate, findTemplatePaginated, statusTemplateDelete } from '../../../src/domain/status';
import { FilterMode, OrderingMode, type RequestAccessConfigureInput, RequestAccessType, type StatusAddInput, StatusOrdering, StatusScope } from '../../../src/generated/graphql';
import { logApp } from '../../../src/config/conf';
import { ENTITY_TYPE_STATUS } from '../../../src/schema/internalObject';
import { fullEntitiesList, storeLoadById } from '../../../src/database/middleware-loader';
import type { BasicStoreEntity, BasicWorkflowStatus } from '../../../src/types/store';
import { createEntity, deleteElementById, internalDeleteElementById, loadEntity, storeLoadByIdWithRefs, updateAttribute } from '../../../src/database/middleware';
import { MEMBER_ACCESS_RIGHT_ADMIN, MEMBER_ACCESS_RIGHT_EDIT } from '../../../src/utils/access';
import { INPUT_GRANTED_REFS, OPENCTI_ADMIN_UUID } from '../../../src/schema/general';
import { ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import * as requestAccessDomain from '../../../src/modules/requestAccess/requestAccess-domain';
import { entitySettingEditField } from '../../../src/modules/entitySetting/entitySetting-domain';
import type { BasicStoreEntityEntitySetting, RequestAccessFlow } from '../../../src/modules/entitySetting/entitySetting-types';
import { addMalware } from '../../../src/domain/malware';
import { resetCacheForEntity } from '../../../src/database/cache';
import { ENTITY_TYPE_WORKFLOW_DEFINITION, ENTITY_TYPE_WORKFLOW_INSTANCE } from '../../../src/modules/workflow/types/workflow-types';
import {
  deleteWorkflowDefinition,
  publishWorkflowDefinition,
  setWorkflowDefinition,
  setWorkflowStatus,
  triggerWorkflowEvent,
} from '../../../src/modules/workflow/domain/workflow-domain';
import { ActionRegistry } from '../../../src/modules/workflow/registry/workflow-actions';
import * as telemetryManager from '../../../src/manager/telemetryManager';
import * as entrepriseEdition from '../../../src/enterprise-edition/ee';
import { UnsupportedError } from '../../../src/config/errors';
import type { AuthUser } from '../../../src/types/user';

export const CREATE_REQUEST_ACCESS_QUERY = gql`
    mutation RequestAccessAdd($input: RequestAccessAddInput!) {
        requestAccessAdd(input: $input)
    }
`;

export const CREATE_MALWARE_QUERY = gql`
    mutation MalwareAdd($input: MalwareAddInput!) {
        malwareAdd(input: $input) {
            id
            name
            description
        }
    }
`;

export const READ_RFI_QUERY = gql`
    query caseRfi($id: String!) {
        caseRfi(id: $id) {
            id
            name
            authorized_members {
              member_id
              access_right
              groups_restriction {
                  id
                  name
              }
            }
            objectParticipant {
                id
                name
            }
            objects {
                edges {
                    node {
                        ... on BasicObject {
                            id
                            entity_type
                            standard_id
                        }
                        ... on BasicRelationship {
                            id
                            entity_type
                            standard_id
                        }
                    }
                }
            }
            x_opencti_request_access
            status {
                id
                template {
                    name
                    color
                }
            }
        }
    }
`;

export const APPROVE_RFI_QUERY = gql`
    mutation ApproveRequestAccess($id: ID!) {
        caseRfiApprove(id: $id){
            id
            x_opencti_workflow_id
        }
    }`;

export const DECLINE_RFI_QUERY = gql`
    mutation DeclineRequestAccess($id: ID!) {
        caseRfiDecline(id: $id){
            id
            x_opencti_workflow_id
        }
    }`;

const STATUS_FIELD_PATCH_QUERY = gql`
    mutation RequestAccessStatusFieldPatch($id: ID!, $input: [EditInput]!) {
        stixDomainObjectEdit(id: $id) {
            fieldPatch(input: $input) {
                id
            }
        }
    }`;

export const QUERY_REQUEST_ACCESS_SETTINGS = gql`
    query SubTypeQuery(
        $id: String!
    ) {
        subType(id: $id) {
            id
            label
            workflowEnabled
            settings {
                id
                availableSettings
                requestAccessConfiguration {
                    approved_status {
                        id
                        template {
                            id
                            name
                        }
                    }
                    declined_status {
                        id
                        template {
                            id
                            name
                        }
                    }
                    approval_admin {
                        id
                        name
                    }
                }
            }
            statuses {
                id
                order
                template {
                    name
                    color
                    id
                }
            }
            statusesRequestAccess {
                id
                order
                template {
                    name
                    color
                    id
                }
            }
        }
    }`;

export const QUERY_ROOT_SETTINGS = gql`
    query RootPrivateQuery {
        settings {
            id
            platform_organization {
                id
            }
            platform_enterprise_edition {
                license_validated
                license_expired
                license_expiration_date
                license_start_date
                license_expiration_prevention
                license_valid_cert
                license_customer
                license_enterprise
                license_platform
                license_platform_match
                license_type
            }
            platform_organization {
                id
                name
            }
            request_access_enabled
        }
    }
`;

export const CONFIGURE_REQUEST_ACCESS_MUTATION = gql`
  mutation RequestAccessConfigure(
      $input: RequestAccessConfigureInput!
  ) {
    requestAccessConfigure(input: $input)
    {
      approval_admin {
          id
      }
        declined_status {
            id
            template {
                id
            }
        }
        approved_status {
            id
            template {
                id
            }
        }
    }
  }
`;

const ADD_REQUEST_ACCESS_STATUS_MUTATION = gql`
    mutation SubTypeWorkflowStatusAddCreationMutation(
        $id: ID!
        $input: StatusAddInput!
    ) {
        subTypeEdit(id: $id) {
            statusAdd(input: $input) {
                id
            }
        }
    }
`;

describe('Add Request Access to an entity and create an RFI.', async () => {
  let caseRfiIdForApproval: string;
  let caseRfiIdForReject: string;
  let caseRfiIdForCounts: string;
  let caseRfiIdForBypass: string;
  let malwareId: string;
  let testOrgId: string;
  let approvedStatusId: string;
  let declinedStatusId: string;
  let amberGroupId: string;
  let greenGroupId: string;
  const editionSpies: Array<{ mockRestore: () => void }> = [];

  beforeAll(() => {
    editionSpies.push(
      vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockResolvedValue(),
      vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(true),
      vi.spyOn(entrepriseEdition, 'isEnterpriseEditionFromSettings').mockReturnValue(true),
    );
  });

  afterAll(() => {
    editionSpies.forEach((spy) => spy.mockRestore());
  });

  it('should enable platform organization', async () => {
    await setOrganization(TEST_ORGANIZATION);

    // Verify initial data required for tests.
    expect(USER_EDITOR.organizations?.some((organization) => organization.name === TEST_ORGANIZATION.name));
    expect(USER_DISINFORMATION_ANALYST.organizations?.some((organization) => organization.name === PLATFORM_ORGANIZATION.name));
  });

  it('should Request Access configuration be created at init', async () => {
    const rfiEntitySettings = await queryAsAdminWithSuccess({
      query: QUERY_REQUEST_ACCESS_SETTINGS,
      variables: { id: ENTITY_TYPE_CONTAINER_CASE_RFI },
    });
    const requestAccessWorkflowSettings = rfiEntitySettings?.data?.subType.settings.requestAccessConfiguration;
    expect(requestAccessWorkflowSettings.approved_status).toBeDefined();
    approvedStatusId = requestAccessWorkflowSettings.approved_status.id;
    expect(requestAccessWorkflowSettings.declined_status).toBeDefined();
    declinedStatusId = requestAccessWorkflowSettings.declined_status.id;

    logApp.info('[TEST] requestAccessWorkflowSettings:', { requestAccessWorkflowSettings });
  });

  it('should request access have more status and be configurable', async () => {
    // ADD 2 status in the list of request access available status
    const allTemplates = await findTemplatePaginated(testContext, ADMIN_USER, {});
    const pendingTemplate = allTemplates.edges.find((template) => template.node.name === 'PENDING');
    expect(pendingTemplate?.node.name).toBe('PENDING');
    logApp.info(`[TEST] pendingTemplate:${pendingTemplate?.node.id}`, { pendingTemplate });

    const closedTemplate = allTemplates.edges.find((template) => template.node.name === 'CLOSED');
    expect(closedTemplate?.node.name).toBe('CLOSED');
    logApp.info(`[TEST] closedTemplate:${closedTemplate?.node.id}`, { closedTemplate });

    const inputPending: StatusAddInput = {
      order: 3,
      scope: StatusScope.RequestAccess,
      template_id: pendingTemplate?.node.id ?? '',
    };
    logApp.info('[TEST] inputPending:', { inputPending });
    await queryAsAdminWithSuccess({
      query: ADD_REQUEST_ACCESS_STATUS_MUTATION,
      variables: {
        input: inputPending,
        id: ENTITY_TYPE_CONTAINER_CASE_RFI,
      },
    });

    const inputClosed: StatusAddInput = {
      order: 3,
      scope: StatusScope.RequestAccess,
      template_id: closedTemplate?.node.id ?? '',
    };
    await queryAsAdminWithSuccess({
      query: ADD_REQUEST_ACCESS_STATUS_MUTATION,
      variables: {
        input: inputClosed,
        id: ENTITY_TYPE_CONTAINER_CASE_RFI,
      },
    });

    // resetCacheForEntity(ENTITY_TYPE_STATUS);
    // resetCacheForEntity(ENTITY_TYPE_ENTITY_SETTING);
    // await waitInSec(3);

    const rfiEntitySettings = await queryAsAdminWithSuccess({
      query: QUERY_REQUEST_ACCESS_SETTINGS,
      variables: { id: ENTITY_TYPE_CONTAINER_CASE_RFI },
    });
    logApp.info('[TEST] rfiEntitySettings:', { rfiEntitySettings });
    // await waitInSec(300);

    const argsFilter = {
      orderBy: StatusOrdering.Order,
      orderMode: OrderingMode.Asc,
      filters: {
        mode: FilterMode.And,
        filters: [{ key: ['type'], values: [ENTITY_TYPE_CONTAINER_CASE_RFI] }, { key: ['scope'], values: [StatusScope.RequestAccess] }],
        filterGroups: [],
      },
    };
    const allRequestAccessStatuses = await fullEntitiesList<BasicWorkflowStatus>(testContext, ADMIN_USER, [ENTITY_TYPE_STATUS], argsFilter);
    logApp.info('[TEST] allRequestAccessStatuses:', { allRequestAccessStatuses });
    const closedStatus = allRequestAccessStatuses.find((status) => status.template_id === closedTemplate?.node.id);
    logApp.info('[TEST] closedStatus:', { closedStatus });
  });

  it('should request access be configurable', async () => {
    const allTemplates = await findTemplatePaginated(testContext, ADMIN_USER, {});

    // All of them are created in data initialization
    const pendingTemplate = allTemplates.edges.find((template) => template.node.name === 'PENDING');
    expect(pendingTemplate?.node.name).toBe('PENDING');

    const closedTemplate = allTemplates.edges.find((template) => template.node.name === 'CLOSED');
    const declinedTemplate = allTemplates.edges.find((template) => template.node.name === 'DECLINED');
    const approvedTemplate = allTemplates.edges.find((template) => template.node.name === 'APPROVED');

    expect(closedTemplate?.node.name).toBe('CLOSED');
    expect(declinedTemplate?.node.name).toBe('DECLINED');
    expect(approvedTemplate?.node.name).toBe('APPROVED');

    amberGroupId = await getGroupIdByName(AMBER_GROUP.name);
    greenGroupId = await getGroupIdByName(GREEN_GROUP.name);
    expect(greenGroupId).toBeDefined();
    expect(amberGroupId).toBeDefined();

    const input: RequestAccessConfigureInput = {
      approved_status_id: pendingTemplate?.node.id,
      declined_status_id: closedTemplate?.node.id,
      approval_admin: [greenGroupId],
    };

    await queryAsAdminWithSuccess({
      query: CONFIGURE_REQUEST_ACCESS_MUTATION,
      variables: {
        input,
      },
    });

    const rfiEntitySettings = await queryAsAdminWithSuccess({
      query: QUERY_REQUEST_ACCESS_SETTINGS,
      variables: { id: ENTITY_TYPE_CONTAINER_CASE_RFI },
    });
    const requestAccessConfiguration = rfiEntitySettings?.data?.subType.settings.requestAccessConfiguration;

    expect(requestAccessConfiguration.approval_admin).toBeDefined();
    expect(requestAccessConfiguration.approval_admin[0].id).toBe(greenGroupId);
    expect(requestAccessConfiguration.approved_status.template.name).toBe('PENDING');
    expect(requestAccessConfiguration.declined_status.template.name).toBe('CLOSED');

    // Back to "Normal" status
    const inputBackToNormal: RequestAccessConfigureInput = {
      approved_status_id: approvedTemplate?.node.id,
      declined_status_id: declinedTemplate?.node.id,
      approval_admin: [amberGroupId],
    };
    await queryAsAdminWithSuccess({
      query: CONFIGURE_REQUEST_ACCESS_MUTATION,
      variables: {
        input: inputBackToNormal,
      },
    });

    const rfiEntitySettingsBackToNormal = await queryAsAdminWithSuccess({
      query: QUERY_REQUEST_ACCESS_SETTINGS,
      variables: { id: ENTITY_TYPE_CONTAINER_CASE_RFI },
    });

    const configurationBackToNormal = rfiEntitySettingsBackToNormal?.data?.subType.settings.requestAccessConfiguration;
    expect(configurationBackToNormal.approved_status.template.name).toBe('APPROVED');
    expect(configurationBackToNormal.declined_status.template.name).toBe('DECLINED');
    expect(configurationBackToNormal.approval_admin).toBeDefined();
    expect(configurationBackToNormal.approval_admin[0].id).toBe(amberGroupId);
  });

  it('should request access be configured', async () => {
    const allTemplates = await findTemplatePaginated(testContext, ADMIN_USER, {});
    const declinedTemplate = allTemplates.edges.find((template) => template.node.name === 'DECLINED');
    const approvedTemplate = allTemplates.edges.find((template) => template.node.name === 'APPROVED');
    expect(declinedTemplate?.node.name).toBe('DECLINED');
    expect(approvedTemplate?.node.name).toBe('APPROVED');

    amberGroupId = await getGroupIdByName(AMBER_GROUP.name);
    expect(amberGroupId).toBeDefined();

    // Back to "Normal" status
    const input: RequestAccessConfigureInput = {
      approved_status_id: approvedTemplate?.node.id,
      declined_status_id: declinedTemplate?.node.id,
      approval_admin: [amberGroupId],
    };

    await queryAsAdminWithSuccess({
      query: CONFIGURE_REQUEST_ACCESS_MUTATION,
      variables: {
        input,
      },
    });

    const rfiEntitySettingsBackToNormal = await queryAsAdminWithSuccess({
      query: QUERY_REQUEST_ACCESS_SETTINGS,
      variables: { id: ENTITY_TYPE_CONTAINER_CASE_RFI },
    });

    const configurationBackToNormal = rfiEntitySettingsBackToNormal?.data?.subType.settings.requestAccessConfiguration;
    expect(configurationBackToNormal.approved_status.template.name).toBe('APPROVED');
    expect(configurationBackToNormal.declined_status.template.name).toBe('DECLINED');
    expect(configurationBackToNormal.approval_admin).toBeDefined();
    expect(configurationBackToNormal.approval_admin[0].id).toBe(amberGroupId);
  });

  it('should create malware with restricted access', async () => {
    const malwareStixId = 'malware--34c9875d-8206-4f4b-bf17-f58d9cf7ebec';
    const MALWARE_TO_CREATE = {
      input: {
        name: 'Malware Request Access',
        stix_id: malwareStixId,
        description: 'Malware for Request Access use case.',
      },
    };
    const malware = await queryAsAdminWithSuccess({
      query: CREATE_MALWARE_QUERY,
      variables: MALWARE_TO_CREATE,
    });
    malwareId = malware.data?.malwareAdd.id;
    expect(malware.data?.malwareAdd.id).toBeDefined();

    const testOrgEntity = await getOrganizationEntity(TEST_ORGANIZATION);
    testOrgId = testOrgEntity.id;
    expect(malwareId).toBeDefined();
    expect(testOrgId).toBeDefined();
  });

  it('should create a Request Access and associated Case RFI (For accept use case)', async () => {
    const requestAccessData = await queryAsAdminWithSuccess({
      query: CREATE_REQUEST_ACCESS_QUERY,
      variables: {
        input: {
          request_access_reason: 'Access needed for test that will accept',
          request_access_entities: [malwareId],
          request_access_members: [testOrgId],
          request_access_type: RequestAccessType.OrganizationSharing,
        },
      },
    });

    expect(requestAccessData).not.toBeNull();
    caseRfiIdForApproval = requestAccessData?.data?.requestAccessAdd;
    expect(caseRfiIdForApproval).not.toBeNull();
  });

  it('should retrieve the created Case RFI with correct authorize members and objects', async () => {
    const getRfiQueryResult = await queryAsAdminWithSuccess({
      query: READ_RFI_QUERY,
      variables: { id: caseRfiIdForApproval },
    });

    expect(getRfiQueryResult?.data?.caseRfi).not.toBeNull();
    expect(getRfiQueryResult?.data?.caseRfi.status.template.name).toEqual('NEW');

    expect(getRfiQueryResult?.data?.caseRfi.authorized_members).toBeDefined();
    expect(getRfiQueryResult?.data?.caseRfi.authorized_members).toEqual([
      {
        member_id: OPENCTI_ADMIN_UUID,
        access_right: MEMBER_ACCESS_RIGHT_ADMIN,
        groups_restriction: [],
      }, {
        member_id: testOrgId,
        access_right: MEMBER_ACCESS_RIGHT_EDIT,
        groups_restriction: [{ id: amberGroupId, name: AMBER_GROUP.name }],
      },
    ]);

    // We need data from database because JSON field x_opencti_request_access is internal (not on API)
    const caseRequestForInformation = await findRFIById(testContext, ADMIN_USER, caseRfiIdForApproval);
    expect(caseRequestForInformation.object).toEqual([malwareId]);

    const action: RequestAccessAction = JSON.parse(caseRequestForInformation.x_opencti_request_access);
    expect(action.status).toBe(ActionStatus.NEW);
    expect(action.workflowMapping).toBeDefined();
    expect(action.workflowMapping.length).toBe(3); // Status for NEW, Approved and Declined.
  });

  it('should accept the created Case RFI first time be ok', async () => {
    // FIXME use a user and not admin !
    /*
      const approvalResult = await queryAsUserWithSuccess(USER_EDITOR, {
        query: APPROVE_RFI_QUERY,
        variables: { id: caseRfiIdForApproval },
      });
      expect(approvalResult?.data?.caseRfiApprove.x_opencti_workflow_id).toBe(approvedStatusId);
    */

    const approvalResult = await queryAsAdminWithSuccess({
      query: APPROVE_RFI_QUERY,
      variables: { id: caseRfiIdForApproval },
    });
    expect(approvalResult?.data?.caseRfiApprove.x_opencti_workflow_id).toBe(approvedStatusId);

    // We need data from database because JSON field x_opencti_request_access is internal (not on API)
    const caseRequestForInformation = await findRFIById(testContext, ADMIN_USER, caseRfiIdForApproval);
    const action: RequestAccessAction = JSON.parse(caseRequestForInformation.x_opencti_request_access);
    expect(action.status).toBe(ActionStatus.APPROVED);

    const getRfiQueryResult = await queryAsAdminWithSuccess({
      query: READ_RFI_QUERY,
      variables: { id: caseRfiIdForApproval },
    });

    expect(getRfiQueryResult?.data?.caseRfi).not.toBeNull();
    expect(caseRequestForInformation.object).toEqual([malwareId]);
    expect(getRfiQueryResult?.data?.caseRfi.status.template.name).toEqual('APPROVED'); // 'APPROVED' coming from data-initialization
  });

  it('should accept the created Case RFI second time be ok too', async () => {
    // FIXME use a user and not admin !
    /*
      const approvalResult = await queryAsUserWithSuccess(USER_EDITOR, {
        query: APPROVE_RFI_QUERY,
        variables: { id: caseRfiIdForApproval },
      });
      */
    const approvalResult = await queryAsAdminWithSuccess({
      query: APPROVE_RFI_QUERY,
      variables: { id: caseRfiIdForApproval },
    });
    expect(approvalResult?.data?.caseRfiApprove.x_opencti_workflow_id).toBe(approvedStatusId);
  });

  it('should create a new Request Access and associated Case RFI (For reject use case)', async () => {
    const requestAccessData = await queryAsUserWithSuccess(USER_DISINFORMATION_ANALYST, {
      query: CREATE_REQUEST_ACCESS_QUERY,
      variables: {
        input: {
          request_access_reason: 'Access needed for test that will refuse',
          request_access_entities: [malwareId],
          request_access_members: [testOrgId],
          request_access_type: 'organization_sharing',
        },
      },
    });
    expect(requestAccessData).not.toBeNull();
    caseRfiIdForReject = requestAccessData?.data?.requestAccessAdd;
    expect(caseRfiIdForReject).not.toBeNull();
  });

  it('should reject the created Case RFI first time be ok', async () => {
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR, {
      query: DECLINE_RFI_QUERY,
      variables: { id: caseRfiIdForReject },
    });
    expect(queryResult?.data?.caseRfiDecline.x_opencti_workflow_id).toBe(declinedStatusId);

    const getRfiQueryResult = await queryAsAdminWithSuccess({
      query: READ_RFI_QUERY,
      variables: { id: caseRfiIdForReject },
    });
    expect(getRfiQueryResult?.data?.caseRfi).not.toBeNull();
    expect(getRfiQueryResult?.data?.caseRfi.status.template.name).toEqual('DECLINED'); // 'DECLINED' coming from data-initialization

    // We need data from database because JSON field x_opencti_request_access is internal (not on API)
    const caseRequestForInformation = await findRFIById(testContext, ADMIN_USER, caseRfiIdForReject);
    const action: RequestAccessAction = JSON.parse(caseRequestForInformation.x_opencti_request_access);
    expect(action.status).toBe(ActionStatus.DECLINED);
  });

  it('should reject the created Case RFI second time be ok too', async () => {
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR, {
      query: DECLINE_RFI_QUERY,
      variables: { input: { id: caseRfiIdForReject }, id: caseRfiIdForReject },
    });
    expect(queryResult?.data?.caseRfiDecline.x_opencti_workflow_id).toBe(declinedStatusId);
  });

  it('should be ok to accept the Case RFI when already rejected', async () => {
    /* FIXME
      const queryResult = await queryAsUserWithSuccess(USER_EDITOR, {
        query: APPROVE_RFI_QUERY,
        variables: { input: { id: caseRfiIdForReject }, id: caseRfiIdForReject },
      });
      */
    const queryResult = await queryAsAdminWithSuccess({
      query: APPROVE_RFI_QUERY,
      variables: { input: { id: caseRfiIdForReject }, id: caseRfiIdForReject },
    });

    expect(queryResult?.data?.caseRfiApprove.x_opencti_workflow_id).toBe(approvedStatusId);
  });

  it('legacy RFI keeps today\'s approve behavior', async () => {
    const requestAccessData = await queryAsUserWithSuccess(USER_DISINFORMATION_ANALYST, {
      query: CREATE_REQUEST_ACCESS_QUERY,
      variables: {
        input: {
          request_access_reason: 'Access needed for the legacy decision counters',
          request_access_entities: [malwareId],
          request_access_members: [testOrgId],
          request_access_type: 'organization_sharing',
        },
      },
    });
    caseRfiIdForCounts = requestAccessData?.data?.requestAccessAdd;
    const approvedCount = vi.spyOn(telemetryManager, 'addRequestAccessApprovedCount');
    const declinedCount = vi.spyOn(telemetryManager, 'addRequestAccessDeclinedCount');
    try {
      const approvalResult = await queryAsAdminWithSuccess({ query: APPROVE_RFI_QUERY, variables: { id: caseRfiIdForCounts } });
      expect(approvalResult?.data?.caseRfiApprove.x_opencti_workflow_id).toBe(approvedStatusId);
      const approvedAction: RequestAccessAction = JSON.parse((await findRFIById(testContext, ADMIN_USER, caseRfiIdForCounts)).x_opencti_request_access);
      expect(approvedAction.status).toBe(ActionStatus.APPROVED);
      expect(approvedCount).toHaveBeenCalledTimes(1);
      expect(declinedCount).not.toHaveBeenCalled();

      const declineResult = await queryAsUserWithSuccess(USER_EDITOR, { query: DECLINE_RFI_QUERY, variables: { id: caseRfiIdForCounts } });
      expect(declineResult?.data?.caseRfiDecline.x_opencti_workflow_id).toBe(declinedStatusId);
      const declinedAction: RequestAccessAction = JSON.parse((await findRFIById(testContext, ADMIN_USER, caseRfiIdForCounts)).x_opencti_request_access);
      expect(declinedAction.status).toBe(ActionStatus.DECLINED);
      expect(declinedCount).toHaveBeenCalledTimes(1);
      expect(approvedCount).toHaveBeenCalledTimes(1);
    } finally {
      approvedCount.mockRestore();
      declinedCount.mockRestore();
    }
  });

  it('bypass still refused on a legacy request-access RFI', async () => {
    const requestAccessData = await queryAsUserWithSuccess(USER_DISINFORMATION_ANALYST, {
      query: CREATE_REQUEST_ACCESS_QUERY,
      variables: {
        input: {
          request_access_reason: 'Access needed for the legacy bypass refusal',
          request_access_entities: [malwareId],
          request_access_members: [testOrgId],
          request_access_type: 'organization_sharing',
        },
      },
    });
    caseRfiIdForBypass = requestAccessData?.data?.requestAccessAdd;
    const { x_opencti_workflow_id: initialStatusId } = await findRFIById(testContext, ADMIN_USER, caseRfiIdForBypass);

    await expect(setWorkflowStatus(testContext, ADMIN_USER, caseRfiIdForBypass, approvedStatusId, false))
      .rejects.toThrow('RequestAccess workflow bypass is not supported');
    await expect(setWorkflowStatus(testContext, ADMIN_USER, caseRfiIdForBypass, approvedStatusId, true))
      .rejects.toThrow('RequestAccess workflow bypass is not supported');
    const rfi = await findRFIById(testContext, ADMIN_USER, caseRfiIdForBypass);
    expect(rfi.x_opencti_workflow_id).toBe(initialStatusId);
    expect(JSON.parse(rfi.x_opencti_request_access).status).toBe(ActionStatus.NEW);
  });

  it('should remove platform organization and test data', async () => {
    await internalDeleteElementById(testContext, ADMIN_USER, malwareId, ENTITY_TYPE_MALWARE);
    await internalDeleteElementById(testContext, ADMIN_USER, caseRfiIdForApproval, ENTITY_TYPE_CONTAINER_CASE_RFI);
    await internalDeleteElementById(testContext, ADMIN_USER, caseRfiIdForReject, ENTITY_TYPE_CONTAINER_CASE_RFI);
    await internalDeleteElementById(testContext, ADMIN_USER, caseRfiIdForCounts, ENTITY_TYPE_CONTAINER_CASE_RFI);
    await internalDeleteElementById(testContext, ADMIN_USER, caseRfiIdForBypass, ENTITY_TYPE_CONTAINER_CASE_RFI);

    // revert platform orga
    await unSetOrganization();
  });
});

describe('Request access decided through workflow transitions', async () => {
  const suffix = Date.now();
  const templateIds = { pending: '', escalated: '', review: '', approved: '', declined: '' };
  let rfiEntitySettings: BasicStoreEntityEntitySetting;
  let initialConfig: RequestAccessFlow | undefined;
  let malwareId: string;
  let testOrganizationId: string;
  const createdRfiIds: string[] = [];
  const editionSpies: Array<{ mockRestore: () => void }> = [];
  let share: ReturnType<typeof vi.spyOn>;
  let notifyResult: ReturnType<typeof vi.spyOn>;
  let approvedCount: ReturnType<typeof vi.spyOn>;
  let declinedCount: ReturnType<typeof vi.spyOn>;

  const definition = () => JSON.stringify({
    initialState: templateIds.pending,
    states: [
      { statusId: templateIds.pending },
      { statusId: templateIds.escalated },
      { statusId: templateIds.review },
      { statusId: templateIds.approved, requestAccessOutcome: 'APPROVED', onEnter: [{ type: 'shareRequestedEntities', params: { organizations: ['AUTHOR'] } }] },
      { statusId: templateIds.declined, requestAccessOutcome: 'DECLINED' },
    ],
    transitions: [
      { from: templateIds.pending, to: templateIds.approved, event: 'Accept' },
      { from: templateIds.pending, to: templateIds.declined, event: 'Reject' },
      // Escalated requests must be reviewed before any decision, and their rejection must be explained.
      { from: templateIds.pending, to: templateIds.escalated, event: 'Escalate' },
      { from: templateIds.escalated, to: templateIds.review, event: 'Review' },
      { from: templateIds.review, to: templateIds.approved, event: 'Accept' },
      { from: templateIds.review, to: templateIds.declined, event: 'Reject', comment: 'required' },
    ],
  });
  const requestAccess = async () => {
    const rfiId = await addRequestAccess(testContext, ADMIN_USER, {
      request_access_reason: 'Access needed for the workflow decision tests',
      request_access_entities: [malwareId],
      request_access_members: [testOrganizationId],
      request_access_type: RequestAccessType.OrganizationSharing,
    });
    createdRfiIds.push(rfiId);
    return rfiId;
  };
  const findInstance = (rfiId: string) => loadEntity<BasicStoreEntity & { currentState?: string }>(testContext, ADMIN_USER, [ENTITY_TYPE_WORKFLOW_INSTANCE], {
    filters: { mode: FilterMode.And, filters: [{ key: ['entity_id'], values: [rfiId] }], filterGroups: [] },
  });
  const loadDecision = async (rfiId: string) => {
    const rfi = await findRFIById(testContext, ADMIN_USER, rfiId);
    return { statusId: rfi.x_opencti_workflow_id, action: JSON.parse(rfi.x_opencti_request_access) as RequestAccessAction };
  };
  const statusIdOf = async (templateId: string) => (await findWorkflowStatusByTemplateId(testContext, ADMIN_USER, templateId)).id;
  const accept = (rfiId: string, user: AuthUser = ADMIN_USER) => triggerWorkflowEvent(testContext, user, rfiId, 'Accept');
  // An RFI whose instance is not created yet, sitting at the status of a later state (e.g. migrated in flight)
  const withoutInstanceAt = async (rfiId: string, templateId: string) => {
    const instance = await findInstance(rfiId);
    await deleteElementById(testContext, ADMIN_USER, instance!.id, ENTITY_TYPE_WORKFLOW_INSTANCE);
    await updateAttribute(testContext, ADMIN_USER, rfiId, ENTITY_TYPE_CONTAINER_CASE_RFI, [
      { key: 'x_opencti_workflow_id', value: [await statusIdOf(templateId)] },
    ], { workflowInternalWrite: true });
    expect(await findInstance(rfiId)).toBeFalsy();
  };

  beforeAll(async () => {
    editionSpies.push(
      vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockResolvedValue(),
      vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(true),
      vi.spyOn(entrepriseEdition, 'isEnterpriseEditionFromSettings').mockReturnValue(true),
    );
    await setOrganization(TEST_ORGANIZATION);
    testOrganizationId = (await getOrganizationEntity(TEST_ORGANIZATION)).id;
    const amberGroupId = await getGroupIdByName(AMBER_GROUP.name);

    rfiEntitySettings = await getRfiEntitySettings(testContext, ADMIN_USER);
    initialConfig = rfiEntitySettings.request_access_workflow;
    // The approvers group: USER_EDITOR (TEST_ORGANIZATION, AMBER_GROUP) can edit the RFIs but not share knowledge.
    await entitySettingEditField(testContext, ADMIN_USER, rfiEntitySettings.id, [
      { key: 'request_access_workflow', value: [{ ...initialConfig, approval_admin: [amberGroupId] }] },
    ]);
    for (const key of Object.keys(templateIds) as Array<keyof typeof templateIds>) {
      const template = await createStatusTemplate(testContext, ADMIN_USER, { name: `RA decision ${key} ${suffix}`, color: '#b83f13' });
      templateIds[key] = template.id;
    }
    const malware = await addMalware(testContext, ADMIN_USER, { name: `Request access decision malware ${suffix}` });
    malwareId = malware.id;
    await setWorkflowDefinition(testContext, ADMIN_USER, ENTITY_TYPE_CONTAINER_CASE_RFI, definition(), StatusScope.RequestAccess);
    await publishWorkflowDefinition(testContext, ADMIN_USER, ENTITY_TYPE_CONTAINER_CASE_RFI, StatusScope.RequestAccess);
    resetCacheForEntity(ENTITY_TYPE_STATUS);
  });

  beforeEach(() => {
    share = vi.spyOn(ActionRegistry, 'shareRequestedEntities');
    notifyResult = vi.spyOn(requestAccessDomain, 'notifyRequestAccessResult');
    approvedCount = vi.spyOn(telemetryManager, 'addRequestAccessApprovedCount');
    declinedCount = vi.spyOn(telemetryManager, 'addRequestAccessDeclinedCount');
  });

  afterEach(() => {
    [share, notifyResult, approvedCount, declinedCount].forEach((spy) => spy.mockRestore());
  });

  afterAll(async () => {
    for (const rfiId of createdRfiIds) {
      await deleteElementById(testContext, ADMIN_USER, rfiId, ENTITY_TYPE_CONTAINER_CASE_RFI);
    }
    await deleteElementById(testContext, ADMIN_USER, malwareId, ENTITY_TYPE_MALWARE);
    // Unlinking leaves the definition entity, which would block the deletion of its status templates.
    const definitionId = (await getRfiEntitySettings(testContext, ADMIN_USER)).request_access_workflow?.workflow_definition_id;
    await deleteWorkflowDefinition(testContext, ADMIN_USER, ENTITY_TYPE_CONTAINER_CASE_RFI, StatusScope.RequestAccess);
    if (definitionId) {
      await deleteElementById(testContext, ADMIN_USER, definitionId, ENTITY_TYPE_WORKFLOW_DEFINITION);
    }
    await entitySettingEditField(testContext, ADMIN_USER, rfiEntitySettings.id, [{ key: 'request_access_workflow', value: [initialConfig] }]);
    const templateIdList = Object.values(templateIds).filter(Boolean);
    for (const templateId of templateIdList) {
      await statusTemplateDelete(testContext, ADMIN_USER, templateId);
    }
    resetCacheForEntity(ENTITY_TYPE_STATUS);
    const leftoverStatuses = await fullEntitiesList<BasicWorkflowStatus>(testContext, ADMIN_USER, [ENTITY_TYPE_STATUS], {
      filters: { mode: FilterMode.And, filters: [{ key: ['template_id'], values: templateIdList }], filterGroups: [] },
    });
    const leftoverDefinition = definitionId ? await storeLoadById(testContext, ADMIN_USER, definitionId, ENTITY_TYPE_WORKFLOW_DEFINITION) : undefined;
    expect(leftoverStatuses).toHaveLength(0);
    expect(leftoverDefinition).toBeUndefined();
    editionSpies.forEach((spy) => spy.mockRestore());
    await unSetOrganization();
  });

  it('Accept shares, sets APPROVED, notifies and counts once', async () => {
    const rfiId = await requestAccess();

    const result = await accept(rfiId);

    expect(result).toMatchObject({ success: true, newState: templateIds.approved });
    expect(share).toHaveBeenCalledTimes(1);
    const malware = await storeLoadByIdWithRefs(testContext, ADMIN_USER, malwareId) as Record<string, any>;
    expect(malware[INPUT_GRANTED_REFS].map((organization: BasicStoreEntity) => organization.internal_id)).toContain(testOrganizationId);
    const { statusId, action } = await loadDecision(rfiId);
    expect(statusId).toBe(await statusIdOf(templateIds.approved));
    expect(action.status).toBe(ActionStatus.APPROVED);
    expect(action.executionDate).toBeDefined();
    expect((await findInstance(rfiId))?.currentState).toBe(templateIds.approved);
    expect(notifyResult).toHaveBeenCalledTimes(1);
    const approver = expect.objectContaining({ id: ADMIN_USER.id });
    expect(notifyResult).toHaveBeenCalledWith(expect.anything(), approver, expect.anything(), ADMIN_USER.id, expect.any(String), ActionStatus.APPROVED);
    expect(approvedCount).toHaveBeenCalledTimes(1);
    expect(declinedCount).not.toHaveBeenCalled();
  });

  it('Reject sets DECLINED and counts declined', async () => {
    const rfiId = await requestAccess();

    const result = await triggerWorkflowEvent(testContext, ADMIN_USER, rfiId, 'Reject');

    expect(result).toMatchObject({ success: true, newState: templateIds.declined });
    expect(share).not.toHaveBeenCalled();
    const { statusId, action } = await loadDecision(rfiId);
    expect(statusId).toBe(await statusIdOf(templateIds.declined));
    expect(action.status).toBe(ActionStatus.DECLINED);
    expect(action.executionDate).toBeDefined();
    expect(notifyResult).toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.anything(), ADMIN_USER.id, expect.any(String), ActionStatus.DECLINED);
    expect(declinedCount).toHaveBeenCalledTimes(1);
    expect(approvedCount).not.toHaveBeenCalled();
  });

  it('user without KNOWLEDGE_ORGANIZATION_RESTRICT cannot enter Approved', async () => {
    const rfiId = await requestAccess();
    const editor = await getAuthUser(USER_EDITOR.id);

    const result = await accept(rfiId, editor);

    expect(result.success).toBe(false);
    expect(result.reason).toContain('You need to be able to edit the RFI and share knowledge');
    expect(share).not.toHaveBeenCalled();
    const { statusId, action } = await loadDecision(rfiId);
    expect(statusId).toBe(await statusIdOf(templateIds.pending));
    expect(action.status).toBe(ActionStatus.NEW);
    expect((await findInstance(rfiId))?.currentState).toBe(templateIds.pending);
    expect(approvedCount).not.toHaveBeenCalled();
  });

  it('share failure leaves the RFI in its previous state with the error', async () => {
    const rfiId = await requestAccess();
    share.mockRejectedValueOnce(UnsupportedError('Element is not sharable at the moment (restricted)'));

    const result = await accept(rfiId);

    expect(result.success).toBe(false);
    expect(result.reason).toContain('Element is not sharable at the moment (restricted)');
    const { statusId, action } = await loadDecision(rfiId);
    expect(statusId).toBe(await statusIdOf(templateIds.pending));
    expect(action.status).toBe(ActionStatus.NEW);
    expect((await findInstance(rfiId))?.currentState).toBe(templateIds.pending);
    expect(notifyResult).not.toHaveBeenCalled();
    expect(approvedCount).not.toHaveBeenCalled();

    // The approver can retry once the share is possible again.
    expect(await accept(rfiId)).toMatchObject({ success: true, newState: templateIds.approved });
    expect((await loadDecision(rfiId)).action.status).toBe(ActionStatus.APPROVED);
    expect(approvedCount).toHaveBeenCalledTimes(1);
  });

  it('second concurrent Accept is rejected and shares nothing more', async () => {
    const rfiId = await requestAccess();

    const results = await Promise.all([accept(rfiId), accept(rfiId)]);

    expect(results.filter((result) => result.success)).toHaveLength(1);
    expect(results.find((result) => !result.success)?.reason).toContain('is not available from status');
    expect(share).toHaveBeenCalledTimes(1);
    expect(notifyResult).toHaveBeenCalledTimes(1);
    expect(approvedCount).toHaveBeenCalledTimes(1);
    expect((await loadDecision(rfiId)).action.status).toBe(ActionStatus.APPROVED);
  });

  it('caseRfiApprove on a workflow-driven RFI fires the Accept transition', async () => {
    const rfiId = await requestAccess();

    const approvalResult = await queryAsAdminWithSuccess({ query: APPROVE_RFI_QUERY, variables: { id: rfiId } });

    expect(approvalResult.data.caseRfiApprove.x_opencti_workflow_id).toBe(await statusIdOf(templateIds.approved));
    expect((await findInstance(rfiId))?.currentState).toBe(templateIds.approved);
    expect(share).toHaveBeenCalledTimes(1);
    expect((await loadDecision(rfiId)).action.status).toBe(ActionStatus.APPROVED);
    expect(notifyResult).toHaveBeenCalledTimes(1);
    expect(approvedCount).toHaveBeenCalledTimes(1);
  });

  it('caseRfiApprove fails when the workflow requires an intermediate step', async () => {
    const rfiId = await requestAccess();
    expect(await triggerWorkflowEvent(testContext, ADMIN_USER, rfiId, 'Escalate')).toMatchObject({ success: true });

    const approvalResult = await queryAsAdmin({ query: APPROVE_RFI_QUERY, variables: { id: rfiId } });

    expect(approvalResult.errors?.[0].message).toBe('No transition to APPROVED is allowed from the current state');
    expect((await findInstance(rfiId))?.currentState).toBe(templateIds.escalated);
    expect((await loadDecision(rfiId)).action.status).toBe(ActionStatus.NEW);
    expect(share).not.toHaveBeenCalled();
    expect(approvedCount).not.toHaveBeenCalled();

    // Once reviewed, the same mutation decides the request.
    expect(await triggerWorkflowEvent(testContext, ADMIN_USER, rfiId, 'Review')).toMatchObject({ success: true });
    await queryAsAdminWithSuccess({ query: APPROVE_RFI_QUERY, variables: { id: rfiId } });
    expect((await findInstance(rfiId))?.currentState).toBe(templateIds.approved);
    expect(approvedCount).toHaveBeenCalledTimes(1);
  });

  it('caseRfiDecline fails when Reject requires a comment', async () => {
    const rfiId = await requestAccess();
    expect(await triggerWorkflowEvent(testContext, ADMIN_USER, rfiId, 'Escalate')).toMatchObject({ success: true });
    expect(await triggerWorkflowEvent(testContext, ADMIN_USER, rfiId, 'Review')).toMatchObject({ success: true });

    const declineResult = await queryAsAdmin({ query: DECLINE_RFI_QUERY, variables: { id: rfiId } });

    expect(declineResult.errors?.[0].message).toBe('This transition requires a comment');
    expect((await findInstance(rfiId))?.currentState).toBe(templateIds.review);
    expect((await loadDecision(rfiId)).action.status).toBe(ActionStatus.NEW);
    expect(notifyResult).not.toHaveBeenCalled();
    expect(declinedCount).not.toHaveBeenCalled();
  });

  it('bypass is allowed on a workflow-driven RFI and runs the share only with actions', async () => {
    const withoutActionsRfiId = await requestAccess();
    const withActionsRfiId = await requestAccess();
    const approvedStatusId = await statusIdOf(templateIds.approved);

    expect(await setWorkflowStatus(testContext, ADMIN_USER, withoutActionsRfiId, approvedStatusId, false)).toMatchObject({ success: true, newState: templateIds.approved });
    expect((await loadDecision(withoutActionsRfiId))).toMatchObject({ statusId: approvedStatusId, action: { status: ActionStatus.APPROVED } });
    expect(share).not.toHaveBeenCalled();
    expect(notifyResult).not.toHaveBeenCalled();
    expect(approvedCount).not.toHaveBeenCalled();

    expect(await setWorkflowStatus(testContext, ADMIN_USER, withActionsRfiId, approvedStatusId, true)).toMatchObject({ success: true, newState: templateIds.approved });
    expect((await loadDecision(withActionsRfiId))).toMatchObject({ statusId: approvedStatusId, action: { status: ActionStatus.APPROVED } });
    expect(share).toHaveBeenCalledTimes(1);
    expect(share).toHaveBeenCalledWith(expect.objectContaining({ triggeringUser: expect.objectContaining({ id: ADMIN_USER.id }) }), expect.anything());
    expect(notifyResult).toHaveBeenCalledTimes(1);
    expect(approvedCount).toHaveBeenCalledTimes(1);
  });

  it('bypass out of Approved never unshares', async () => {
    const rfiId = await requestAccess();
    expect(await accept(rfiId)).toMatchObject({ success: true, newState: templateIds.approved });
    const pendingStatusId = await statusIdOf(templateIds.pending);

    expect(await setWorkflowStatus(testContext, ADMIN_USER, rfiId, pendingStatusId, true)).toMatchObject({ success: true, newState: templateIds.pending });

    expect((await findInstance(rfiId))?.currentState).toBe(templateIds.pending);
    expect((await loadDecision(rfiId))).toMatchObject({ statusId: pendingStatusId, action: { status: ActionStatus.NEW } });
    const malware = await storeLoadByIdWithRefs(testContext, ADMIN_USER, malwareId) as Record<string, any>;
    expect(malware[INPUT_GRANTED_REFS].map((organization: BasicStoreEntity) => organization.internal_id)).toContain(testOrganizationId);
    expect(approvedCount).toHaveBeenCalledTimes(1);
    expect(declinedCount).not.toHaveBeenCalled();
  });

  it('caseRfiApprove and caseRfiDecline decide from the status of an RFI without instance yet', async () => {
    const escalatedRfiId = await requestAccess();
    await withoutInstanceAt(escalatedRfiId, templateIds.escalated);

    const approvalResult = await queryAsAdmin({ query: APPROVE_RFI_QUERY, variables: { id: escalatedRfiId } });

    expect(approvalResult.errors?.[0].message).toBe('No transition to APPROVED is allowed from the current state');
    expect((await loadDecision(escalatedRfiId))).toMatchObject({ statusId: await statusIdOf(templateIds.escalated), action: { status: ActionStatus.NEW } });

    const reviewedRfiId = await requestAccess();
    await withoutInstanceAt(reviewedRfiId, templateIds.review);

    const declineResult = await queryAsAdmin({ query: DECLINE_RFI_QUERY, variables: { id: reviewedRfiId } });

    expect(declineResult.errors?.[0].message).toBe('This transition requires a comment');
    expect((await loadDecision(reviewedRfiId)).action.status).toBe(ActionStatus.NEW);
    expect(declinedCount).not.toHaveBeenCalled();

    await queryAsAdminWithSuccess({ query: APPROVE_RFI_QUERY, variables: { id: reviewedRfiId } });

    const instance = await findInstance(reviewedRfiId) as BasicStoreEntity & { currentState?: string; history?: string };
    expect(instance?.currentState).toBe(templateIds.approved);
    expect(JSON.parse(instance?.history ?? '[]').map((entry: { state: string }) => entry.state)).toEqual([templateIds.review, templateIds.approved]);
    expect((await loadDecision(reviewedRfiId)).action.status).toBe(ActionStatus.APPROVED);
    expect(share).toHaveBeenCalledTimes(1);
    expect(approvedCount).toHaveBeenCalledTimes(1);
  });

  it('caseRfiDecline is refused to a user without KNOWLEDGE_ORGANIZATION_RESTRICT', async () => {
    const rfiId = await requestAccess();

    const declineResult = await queryAsUser(USER_EDITOR, { query: DECLINE_RFI_QUERY, variables: { id: rfiId } });

    expect(declineResult.errors?.[0].message).toContain('You need to be able to edit the RFI and share knowledge');
    expect((await loadDecision(rfiId))).toMatchObject({ statusId: await statusIdOf(templateIds.pending), action: { status: ActionStatus.NEW } });
    expect((await findInstance(rfiId))?.currentState).toBe(templateIds.pending);
    expect(notifyResult).not.toHaveBeenCalled();
    expect(declinedCount).not.toHaveBeenCalled();
  });

  it('bypass with actions into Declined records the decline without sharing', async () => {
    const rfiId = await requestAccess();
    const declinedStatusId = await statusIdOf(templateIds.declined);

    expect(await setWorkflowStatus(testContext, ADMIN_USER, rfiId, declinedStatusId, true)).toMatchObject({ success: true, newState: templateIds.declined });

    expect((await loadDecision(rfiId))).toMatchObject({ statusId: declinedStatusId, action: { status: ActionStatus.DECLINED } });
    expect(share).not.toHaveBeenCalled();
    expect(notifyResult).toHaveBeenCalledTimes(1);
    expect(notifyResult).toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.anything(), ADMIN_USER.id, expect.any(String), ActionStatus.DECLINED);
    expect(declinedCount).toHaveBeenCalledTimes(1);
    expect(approvedCount).not.toHaveBeenCalled();
  });

  describe('direct writes of the status', () => {
    const outcomeRejection = 'Approved and Declined can only be reached or left through the workflow';
    const patchStatus = async (rfiId: string, templateId: string) => queryAsAdmin({
      query: STATUS_FIELD_PATCH_QUERY,
      variables: { id: rfiId, input: [{ key: 'x_opencti_workflow_id', value: [await statusIdOf(templateId)] }] },
    });

    it('fieldPatch to the Approved status is rejected', async () => {
      const rfiId = await requestAccess();

      const patchResult = await patchStatus(rfiId, templateIds.approved);

      expect(patchResult.errors?.[0].message).toBe(outcomeRejection);
      expect((await loadDecision(rfiId))).toMatchObject({ statusId: await statusIdOf(templateIds.pending), action: { status: ActionStatus.NEW } });
      expect((await findInstance(rfiId))?.currentState).toBe(templateIds.pending);
      expect(share).not.toHaveBeenCalled();
      expect(approvedCount).not.toHaveBeenCalled();
    });

    it('fieldPatch out of Declined is rejected', async () => {
      const rfiId = await requestAccess();
      expect(await triggerWorkflowEvent(testContext, ADMIN_USER, rfiId, 'Reject')).toMatchObject({ success: true });

      const patchResult = await patchStatus(rfiId, templateIds.pending);

      expect(patchResult.errors?.[0].message).toBe(outcomeRejection);
      expect((await loadDecision(rfiId))).toMatchObject({ statusId: await statusIdOf(templateIds.declined), action: { status: ActionStatus.DECLINED } });
      expect((await findInstance(rfiId))?.currentState).toBe(templateIds.declined);
    });

    it('fieldPatch between two intermediate states is still synced', async () => {
      const rfiId = await requestAccess();

      await queryAsAdminWithSuccess({
        query: STATUS_FIELD_PATCH_QUERY,
        variables: { id: rfiId, input: [{ key: 'x_opencti_workflow_id', value: [await statusIdOf(templateIds.escalated)] }] },
      });

      expect((await loadDecision(rfiId))).toMatchObject({ statusId: await statusIdOf(templateIds.escalated), action: { status: ActionStatus.NEW } });
      expect((await findInstance(rfiId))?.currentState).toBe(templateIds.escalated);
    });

    it('workflow internal writes are not blocked', async () => {
      const rfiId = await requestAccess();
      const approvedStatusId = await statusIdOf(templateIds.approved);

      await updateAttribute(testContext, ADMIN_USER, rfiId, ENTITY_TYPE_CONTAINER_CASE_RFI, [
        { key: 'x_opencti_workflow_id', value: [approvedStatusId] },
      ], { workflowInternalWrite: true });

      expect((await loadDecision(rfiId)).statusId).toBe(approvedStatusId);
    });

    it('fieldPatch of an RFI without instance yet into Approved is rejected', async () => {
      const rfiId = await requestAccess();
      await withoutInstanceAt(rfiId, templateIds.review);

      const patchResult = await patchStatus(rfiId, templateIds.approved);

      expect(patchResult.errors?.[0].message).toBe(outcomeRejection);
      expect((await loadDecision(rfiId))).toMatchObject({ statusId: await statusIdOf(templateIds.review), action: { status: ActionStatus.NEW } });
      expect(share).not.toHaveBeenCalled();
    });

    it('upsert into the Approved status is rejected', async () => {
      const rfiId = await requestAccess();
      const rfi = await findRFIById(testContext, ADMIN_USER, rfiId);

      await expect(createEntity(testContext, ADMIN_USER, {
        name: rfi.name,
        created: rfi.created,
        x_opencti_workflow_id: await statusIdOf(templateIds.approved),
      }, ENTITY_TYPE_CONTAINER_CASE_RFI)).rejects.toThrow(outcomeRejection);

      expect((await loadDecision(rfiId))).toMatchObject({ statusId: await statusIdOf(templateIds.pending), action: { status: ActionStatus.NEW } });
      expect((await findInstance(rfiId))?.currentState).toBe(templateIds.pending);
    });
  });

  it('a plain RFI on a request access status stays on the legacy flow', async () => {
    const plainRfi = await addCaseRfi(testContext, ADMIN_USER, { name: `Plain RFI on a request access status ${suffix}`, x_opencti_workflow_id: await statusIdOf(templateIds.pending) });
    createdRfiIds.push(plainRfi.id);

    const approvalResult = await queryAsAdmin({ query: APPROVE_RFI_QUERY, variables: { id: plainRfi.id } });

    expect(approvalResult.errors?.[0].message).toBe('This RFI is not compatible');
    await expect(setWorkflowStatus(testContext, ADMIN_USER, plainRfi.id, await statusIdOf(templateIds.approved), true))
      .rejects.toThrow('RequestAccess workflow bypass is not supported');
    expect(share).not.toHaveBeenCalled();
    expect(approvedCount).not.toHaveBeenCalled();
  });
});

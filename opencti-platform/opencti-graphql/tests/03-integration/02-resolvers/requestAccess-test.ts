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
import { findById as findRFIById } from '../../../src/modules/case/case-rfi/case-rfi-domain';
import { unSetOrganization, setOrganization, queryAsAdminWithSuccess, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
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
import { deleteElementById, internalDeleteElementById, loadEntity, storeLoadByIdWithRefs } from '../../../src/database/middleware';
import { MEMBER_ACCESS_RIGHT_ADMIN, MEMBER_ACCESS_RIGHT_EDIT } from '../../../src/utils/access';
import { INPUT_GRANTED_REFS, OPENCTI_ADMIN_UUID } from '../../../src/schema/general';
import { ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import * as requestAccessDomain from '../../../src/modules/requestAccess/requestAccess-domain';
import { entitySettingEditField } from '../../../src/modules/entitySetting/entitySetting-domain';
import type { BasicStoreEntityEntitySetting, RequestAccessFlow } from '../../../src/modules/entitySetting/entitySetting-types';
import { addMalware } from '../../../src/domain/malware';
import { resetCacheForEntity } from '../../../src/database/cache';
import { ENTITY_TYPE_WORKFLOW_DEFINITION, ENTITY_TYPE_WORKFLOW_INSTANCE } from '../../../src/modules/workflow/types/workflow-types';
import { deleteWorkflowDefinition, publishWorkflowDefinition, setWorkflowDefinition, triggerWorkflowEvent } from '../../../src/modules/workflow/domain/workflow-domain';
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

  it('should remove platform organization and test data', async () => {
    await internalDeleteElementById(testContext, ADMIN_USER, malwareId, ENTITY_TYPE_MALWARE);
    await internalDeleteElementById(testContext, ADMIN_USER, caseRfiIdForApproval, ENTITY_TYPE_CONTAINER_CASE_RFI);
    await internalDeleteElementById(testContext, ADMIN_USER, caseRfiIdForReject, ENTITY_TYPE_CONTAINER_CASE_RFI);

    // revert platform orga
    await unSetOrganization();
  });
});

describe('Request access decided through workflow transitions', async () => {
  const suffix = Date.now();
  const templateIds = { pending: '', approved: '', declined: '' };
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
      { statusId: templateIds.approved, requestAccessOutcome: 'APPROVED', onEnter: [{ type: 'shareRequestedEntities', params: { organizations: ['AUTHOR'] } }] },
      { statusId: templateIds.declined, requestAccessOutcome: 'DECLINED' },
    ],
    transitions: [
      { from: templateIds.pending, to: templateIds.approved, event: 'Accept' },
      { from: templateIds.pending, to: templateIds.declined, event: 'Reject' },
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
});

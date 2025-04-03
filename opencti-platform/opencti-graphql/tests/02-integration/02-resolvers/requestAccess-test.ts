import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import {
  ADMIN_USER,
  AMBER_GROUP,
  getGroupIdByName,
  GREEN_GROUP,
  PLATFORM_ORGANIZATION,
  TEST_ORGANIZATION,
  testContext,
  USER_DISINFORMATION_ANALYST,
  USER_EDITOR
} from '../../utils/testQuery';
import { findById as findRFIById } from '../../../src/modules/case/case-rfi/case-rfi-domain';
import { enableCEAndUnSetOrganization, enableEEAndSetOrganization, queryAsAdminWithSuccess, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { getOrganizationEntity } from '../../utils/domainQueryHelper';
import { ActionStatus, type RequestAccessAction } from '../../../src/modules/requestAccess/requestAccess-domain';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../../src/modules/case/case-rfi/case-rfi-types';
import { findAllTemplates, } from '../../../src/domain/status';
import { FilterMode, OrderingMode, type RequestAccessConfigureInput, RequestAccessType, type StatusAddInput, StatusOrdering, StatusScope } from '../../../src/generated/graphql';
import { logApp } from '../../../src/config/conf';
import { ENTITY_TYPE_STATUS } from '../../../src/schema/internalObject';
import { listAllEntities } from '../../../src/database/middleware-loader';
import type { BasicWorkflowStatus } from '../../../src/types/store';
import { internalDeleteElementById } from '../../../src/database/middleware';
import { MEMBER_ACCESS_RIGHT_ADMIN, MEMBER_ACCESS_RIGHT_EDIT } from '../../../src/utils/access';
import { OPENCTI_ADMIN_UUID } from '../../../src/schema/general';

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

  it('should enable platform organization', async () => {
    await enableEEAndSetOrganization(TEST_ORGANIZATION);

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
    const allTemplates = await findAllTemplates(testContext, ADMIN_USER, {});
    const pendingTemplate = allTemplates.edges.find((template) => template.node.name === 'PENDING');
    expect(pendingTemplate?.node.name).toBe('PENDING');
    logApp.info(`[TEST] pendingTemplate:${pendingTemplate?.node.id}`, { pendingTemplate });

    const closedTemplate = allTemplates.edges.find((template) => template.node.name === 'CLOSED');
    expect(closedTemplate?.node.name).toBe('CLOSED');
    logApp.info(`[TEST] closedTemplate:${closedTemplate?.node.id}`, { closedTemplate });

    const inputPending: StatusAddInput = {
      order: 3,
      scope: StatusScope.RequestAccess,
      template_id: pendingTemplate?.node.id ?? ''
    };
    logApp.info('[TEST] inputPending:', { inputPending });
    await queryAsAdminWithSuccess({
      query: ADD_REQUEST_ACCESS_STATUS_MUTATION,
      variables: {
        input: inputPending,
        id: ENTITY_TYPE_CONTAINER_CASE_RFI
      },
    });

    const inputClosed: StatusAddInput = {
      order: 3,
      scope: StatusScope.RequestAccess,
      template_id: closedTemplate?.node.id ?? ''
    };
    await queryAsAdminWithSuccess({
      query: ADD_REQUEST_ACCESS_STATUS_MUTATION,
      variables: {
        input: inputClosed,
        id: ENTITY_TYPE_CONTAINER_CASE_RFI
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
      connectionFormat: false
    };
    const allRequestAccessStatuses = await listAllEntities<BasicWorkflowStatus>(testContext, ADMIN_USER, [ENTITY_TYPE_STATUS], argsFilter);
    logApp.info('[TEST] allRequestAccessStatuses:', { allRequestAccessStatuses });
    const closedStatus = allRequestAccessStatuses.find((status) => status.template_id === closedTemplate?.node.id);
    logApp.info('[TEST] closedStatus:', { closedStatus });
  });

  it('should request access be configurable', async () => {
    const allTemplates = await findAllTemplates(testContext, ADMIN_USER, {});

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
      approval_admin: [greenGroupId]
    };

    await queryAsAdminWithSuccess({
      query: CONFIGURE_REQUEST_ACCESS_MUTATION,
      variables: {
        input
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
      approval_admin: [amberGroupId]
    };
    await queryAsAdminWithSuccess({
      query: CONFIGURE_REQUEST_ACCESS_MUTATION,
      variables: {
        input: inputBackToNormal
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
    const allTemplates = await findAllTemplates(testContext, ADMIN_USER, {});
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
      approval_admin: [amberGroupId]
    };

    await queryAsAdminWithSuccess({
      query: CONFIGURE_REQUEST_ACCESS_MUTATION,
      variables: {
        input
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
    console.log('requestAccessData:', requestAccessData);
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
        groups_restriction: []
      }, {
        member_id: testOrgId,
        access_right: MEMBER_ACCESS_RIGHT_EDIT,
        groups_restriction: [{ id: amberGroupId, name: AMBER_GROUP.name }]
      }
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
    const approvalResult = await queryAsUserWithSuccess(USER_EDITOR.client, {
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
      variables: { id: caseRfiIdForApproval }
    });

    expect(getRfiQueryResult?.data?.caseRfi).not.toBeNull();
    expect(caseRequestForInformation.object).toEqual([malwareId]);
    expect(getRfiQueryResult?.data?.caseRfi.status.template.name).toEqual('APPROVED'); // 'APPROVED' coming from data-initialization
  });

  it('should accept the created Case RFI second time be ok too', async () => {
    // FIXME use a user and not admin !
    /*
    const approvalResult = await queryAsUserWithSuccess(USER_EDITOR.client, {
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
    const requestAccessData = await queryAsUserWithSuccess(USER_DISINFORMATION_ANALYST.client, {
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
    // FIXME use a user and not admin !
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR.client, {
      query: DECLINE_RFI_QUERY,
      variables: { id: caseRfiIdForReject },
    });
    expect(queryResult?.data?.caseRfiDecline.x_opencti_workflow_id).toBe(declinedStatusId);

    const getRfiQueryResult = await queryAsAdminWithSuccess({
      query: READ_RFI_QUERY,
      variables: { id: caseRfiIdForReject }
    });
    expect(getRfiQueryResult?.data?.caseRfi).not.toBeNull();
    expect(getRfiQueryResult?.data?.caseRfi.status.template.name).toEqual('DECLINED'); // 'DECLINED' coming from data-initialization

    // We need data from database because JSON field x_opencti_request_access is internal (not on API)
    const caseRequestForInformation = await findRFIById(testContext, ADMIN_USER, caseRfiIdForReject);
    const action: RequestAccessAction = JSON.parse(caseRequestForInformation.x_opencti_request_access);
    expect(action.status).toBe(ActionStatus.DECLINED);
  });

  it('should reject the created Case RFI second time be ok too', async () => {
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR.client, {
      query: DECLINE_RFI_QUERY,
      variables: { input: { id: caseRfiIdForReject }, id: caseRfiIdForReject },
    });
    expect(queryResult?.data?.caseRfiDecline.x_opencti_workflow_id).toBe(declinedStatusId);
  });

  it('should be ok to accept the Case RFI when already rejected', async () => {
    /* FIXME
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR.client, {
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
    await internalDeleteElementById(testContext, ADMIN_USER, malwareId);
    await internalDeleteElementById(testContext, ADMIN_USER, caseRfiIdForApproval);
    await internalDeleteElementById(testContext, ADMIN_USER, caseRfiIdForReject);

    // revert platform orga
    await enableCEAndUnSetOrganization();
  });
});

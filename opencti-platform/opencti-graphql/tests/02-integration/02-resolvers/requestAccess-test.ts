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
import { enableCEAndUnSetOrganization, enableEEAndSetOrganization, queryAsAdminWithSuccess, queryAsUserIsExpectedError, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { getOrganizationEntity } from '../../utils/domainQueryHelper';
import { ActionStatus, type RequestAccessAction } from '../../../src/modules/requestAccess/requestAccess-domain';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../../src/modules/case/case-rfi/case-rfi-types';
import { listEntitiesPaginated } from '../../../src/database/middleware-loader';
import type { BasicStoreEntity } from '../../../src/types/store';
import { ENTITY_TYPE_STATUS_TEMPLATE } from '../../../src/schema/internalObject';
import { findAllTemplates } from '../../../src/domain/status';
import { internalDeleteElementById } from '../../../src/database/middleware';
import { StatusScope } from '../../../src/generated/graphql';

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
              id
              access_right
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
        }
    }`;

const READ_SETTINGS_QUERY = gql`
    query settings {
        settings {
            id
            request_access_enabled
        }
    }
`;

export const MUTATION_ENABLE_RFI_WORKFLOW = gql`
    mutation SubTypeWorkflowStatusAddCreationMutation(
    $id: ID!
    $input: StatusAddInput!
) {
    subTypeEdit(id: $id) {
        statusAdd(input: $input) {
            id
            label
            workflowEnabled
            statuses {
                id
                order
                template {
                    name
                    color
                    id
                }
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

describe('Add Request Access to an entity and create an RFI.'
  + 'USER_EDITOR is used as platform admin (in TEST_ORGANIZATION org),'
  + 'USER_DISINFORMATION_ANALYST is used as user that request access to knowledge.', async () => {
  let caseRfiIdForApproval: string;
  let caseRfiIdForReject: string;
  let malwareId: string;
  let testOrgId: string;
  let newStatusId: string;
  let inProgressStatusId: string;
  let approvedStatusId: string;
  let declinedStatusId: string;
  let amberGroupId: string;
  let greenGroupId: string;

  it('Request access feature must be disabled when platform orga is not set', async () => {
    const platformSettings = await queryAsAdminWithSuccess({
      query: QUERY_ROOT_SETTINGS,
      variables: {}
    });
    // If default configuration for test changes and platform_organization is setup, this it step has no meaning anymore.
    expect(platformSettings?.data?.settings.platform_organization).toBeNull();
    expect(platformSettings?.data?.settings.request_access_enabled).toBeFalsy();
  });

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
  });

  it('should throw error when configuration is missing for Request Access feature', async () => {
    // this will only be true the first time, if you re-run tests without init data you might have this step fail.
    const platformSettings = await queryAsAdminWithSuccess({
      query: READ_SETTINGS_QUERY,
      variables: {},
    });
    expect(platformSettings?.data?.settings.request_access_enabled).toBeDefined();
    expect(platformSettings?.data?.settings.request_access_enabled).toBeFalsy();

    // Calling Add access request should throw exception
    await queryAsUserIsExpectedError(USER_EDITOR.client, {
      query: CREATE_REQUEST_ACCESS_QUERY,
      variables: {
        input: {
          request_access_reason: 'This is going to fail',
          request_access_entities: ['1234'],
          request_access_members: ['1234'],
          request_access_type: 'organization_sharing',
        },
      },
    });
  });

  it('should RFI workflow enabled with at least one status', async () => {
    const statusTemplateId_NEW = await listEntitiesPaginated<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_STATUS_TEMPLATE], { search: '"NEW"' });
    expect(statusTemplateId_NEW.edges[0].node.name).toBe('NEW');
    expect(statusTemplateId_NEW.edges[0].node.internal_id).toBeDefined();
    newStatusId = statusTemplateId_NEW.edges[0].node.internal_id;

    const statusTemplateId_IN_PROGRESS = await listEntitiesPaginated<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_STATUS_TEMPLATE], { search: '"IN_PROGRESS"' });
    inProgressStatusId = statusTemplateId_IN_PROGRESS.edges[0].node.internal_id;

    // To verify 'NEW' usage, let's have 2 status created in reverse order.
    await queryAsAdminWithSuccess({
      query: MUTATION_ENABLE_RFI_WORKFLOW,
      variables: {
        id: ENTITY_TYPE_CONTAINER_CASE_RFI,
        input: {
          order: 2,
          template_id: inProgressStatusId,
          scope: StatusScope.Global,
        }
      },
    });

    await queryAsAdminWithSuccess({
      query: MUTATION_ENABLE_RFI_WORKFLOW,
      variables: {
        id: ENTITY_TYPE_CONTAINER_CASE_RFI,
        input: {
          order: 0,
          template_id: newStatusId,
          scope: StatusScope.Global,
        }
      },
    });
    const rfiEntitySettingsWithWorkflow = await queryAsAdminWithSuccess({
      query: QUERY_REQUEST_ACCESS_SETTINGS,
      variables: { id: ENTITY_TYPE_CONTAINER_CASE_RFI },
    });

    expect(rfiEntitySettingsWithWorkflow?.data?.subType.workflowEnabled).toBeTruthy();

    // only workflow statuses should be in statuses, not request-access one
    const workflowStatuses = rfiEntitySettingsWithWorkflow?.data?.subType.statuses;
    expect(workflowStatuses.some((status: any) => status.template.name === 'NEW')).toBeTruthy();
    expect(workflowStatuses.some((status: any) => status.template.name === 'IN_PROGRESS')).toBeTruthy();
    expect(workflowStatuses.some((status: any) => status.template.name === 'DECLINED')).toBeFalsy();
    expect(workflowStatuses.some((status: any) => status.template.name === 'APPROVED')).toBeFalsy();
  });

  it('should request access be configurable', async () => {
    const allTemplates = await findAllTemplates(testContext, ADMIN_USER, {});

    // All of them are created in data initialization
    const newTemplate = allTemplates.edges.find((template) => template.node.name === 'NEW');
    const closedTemplate = allTemplates.edges.find((template) => template.node.name === 'CLOSED');
    const declinedTemplate = allTemplates.edges.find((template) => template.node.name === 'DECLINED');
    const approvedTemplate = allTemplates.edges.find((template) => template.node.name === 'APPROVED');
    expect(newTemplate?.node.name).toBe('NEW');
    expect(closedTemplate?.node.name).toBe('CLOSED');
    expect(declinedTemplate?.node.name).toBe('DECLINED');
    expect(approvedTemplate?.node.name).toBe('APPROVED');

    amberGroupId = await getGroupIdByName(AMBER_GROUP.name);
    greenGroupId = await getGroupIdByName(GREEN_GROUP.name);
    expect(amberGroupId).toBeDefined();

    await queryAsAdminWithSuccess({
      query: CONFIGURE_REQUEST_ACCESS_MUTATION,
      variables: {
        input: {
          approve_status_template_id: newTemplate?.node.id,
          decline_status_template_id: closedTemplate?.node.id,
          approval_admin: [greenGroupId]
        }
      },
    });

    const rfiEntitySettings = await queryAsAdminWithSuccess({
      query: QUERY_REQUEST_ACCESS_SETTINGS,
      variables: { id: ENTITY_TYPE_CONTAINER_CASE_RFI },
    });
    const requestAccessConfiguration = rfiEntitySettings?.data?.subType.settings.requestAccessConfiguration;

    expect(requestAccessConfiguration.approval_admin).toBeDefined();
    expect(requestAccessConfiguration.approval_admin[0].id).toBe(greenGroupId);
    expect(requestAccessConfiguration.approved_status.template.name).toBe('NEW');
    expect(requestAccessConfiguration.declined_status.template.name).toBe('CLOSED');

    // Back to "Normal" status
    await queryAsAdminWithSuccess({
      query: CONFIGURE_REQUEST_ACCESS_MUTATION,
      variables: {
        input: {
          approve_status_template_id: approvedTemplate?.node.id,
          decline_status_template_id: declinedTemplate?.node.id,
          approval_admin: [amberGroupId]
        }
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
  });

  it('should create a Request Access and associated Case RFI (For accept use case)', async () => {
    const requestAccessData = await queryAsUserWithSuccess(USER_DISINFORMATION_ANALYST.client, {
      query: CREATE_REQUEST_ACCESS_QUERY,
      variables: {
        input: {
          request_access_reason: 'Access needed for test that will accept',
          request_access_entities: [malwareId],
          request_access_members: [testOrgId],
          request_access_type: 'organization_sharing',
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
        id: amberGroupId,
        access_right: 'admin'
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

    // revert workflow config to zero workflow statuses
    // await statusDelete(testContext, ADMIN_USER, ENTITY_TYPE_CONTAINER_CASE_RFI, newStatusId);
    // await statusDelete(testContext, ADMIN_USER, ENTITY_TYPE_CONTAINER_CASE_RFI, inProgressStatusId);
    // const rfiWorkflowStatus = await listEntitiesPaginated<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_STATUS]);
    // logApp.info('At the end statuses => ', { rfiWorkflowStatus });

    // revert platform orga
    await enableCEAndUnSetOrganization();
  });
});

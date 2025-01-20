import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, getUserIdByEmail, PLATFORM_ORGANIZATION, TEST_ORGANIZATION, testContext, USER_DISINFORMATION_ANALYST, USER_EDITOR } from '../../utils/testQuery';
import { findById as findRFIById } from '../../../src/modules/case/case-rfi/case-rfi-domain';
import { enableCEAndUnSetOrganization, enableEEAndSetOrganization, queryAsAdminWithSuccess, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { getOrganizationEntity } from '../../utils/domainQueryHelper';
import { internalDeleteElementById } from '../../../src/database/middleware';
import type { RequestAccessAction } from '../../../src/modules/requestAccess/requestAccess-domain';
import { ActionStatus } from '../../../src/generated/graphql';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../../src/modules/case/case-rfi/case-rfi-types';
import { logApp } from '../../../src/config/conf';
import { listEntitiesPaginated } from '../../../src/database/middleware-loader';
import type { BasicStoreEntity } from '../../../src/types/store';
import { ENTITY_TYPE_STATUS_TEMPLATE } from '../../../src/schema/internalObject';

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
        }
    }
`;

export const APPROVE_RFI_QUERY = gql`
    mutation ApproveRequestAccess($id: ID!) {
        requestAccessApprove(id: $id){
            action_executed,
            action_status,
            action_date
        }
    }`;

export const DECLINE_RFI_QUERY = gql`
    mutation DeclineRequestAccess($id: ID!) {
        requestAccessDecline(id: $id){
            action_executed,
            action_status,
            action_date
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
                request_access_workflow {
                    approved_workflow_id
                    declined_workflow_id
                    workflow
                }
                requestAccessStatus {
                    id
                    color
                    name
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

describe('Add Request Access to an entity and create an RFI.'
  + 'USER_EDITOR is used as platform admin (in TEST_ORGANIZATION org),'
  + 'USER_DISINFORMATION_ANALYST is used as user that request access to knowledge.', async () => {
  let caseRfiIdForApproval: string;
  let caseRfiIdForReject: string;
  let malwareId: string;
  let testOrgId: string;
  let userEditorId: string;
  let userAnalystId: string;
  let newStatusId: string;

  it.todo('TODO what to expect when EE is not enabled ?', async () => {

  });

  it('should enable platform organization', async () => {
    await enableEEAndSetOrganization(TEST_ORGANIZATION);
    userEditorId = await getUserIdByEmail(USER_EDITOR.email);
    userAnalystId = await getUserIdByEmail(USER_DISINFORMATION_ANALYST.email);

    // Verify initial data required for tests.
    expect(USER_EDITOR.organizations?.some((organization) => organization.name === TEST_ORGANIZATION.name));
    expect(USER_DISINFORMATION_ANALYST.organizations?.some((organization) => organization.name === PLATFORM_ORGANIZATION.name));
  });

  it('should Request Access configuration be created at init', async () => {
    const rfiEntitySettings = await queryAsAdminWithSuccess({
      query: QUERY_REQUEST_ACCESS_SETTINGS,
      variables: { id: ENTITY_TYPE_CONTAINER_CASE_RFI },
    });
    const requestAccessWorkflowSettings = rfiEntitySettings?.data?.subType.settings.request_access_workflow;
    const requestAccessWorkflowStatuses = rfiEntitySettings?.data?.subType.settings.requestAccessStatus;
    expect(requestAccessWorkflowSettings.approved_workflow_id).toBeDefined();
    expect(requestAccessWorkflowSettings.declined_workflow_id).toBeDefined();
    expect(requestAccessWorkflowStatuses.length).toBe(2);
  });

  it.todo('TODO what to expect when workflow is not enabled on RFI ?', async () => {

  });

  it('should RFI workflow enabled with at least one status', async () => {
    const statusTemplateId_NEW = await listEntitiesPaginated<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_STATUS_TEMPLATE], { search: '"NEW"' });

    expect(statusTemplateId_NEW.edges[0].node.name).toBe('NEW');
    expect(statusTemplateId_NEW.edges[0].node.internal_id).toBeDefined();
    newStatusId = statusTemplateId_NEW.edges[0].node.internal_id;

    const statusTemplateId_IN_PROGRESS = await listEntitiesPaginated<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_STATUS_TEMPLATE], { search: '"IN_PROGRESS"' });
    const inProgressStatusId = statusTemplateId_IN_PROGRESS.edges[0].node.internal_id;

    // To verify 'NEW' usage, let's have 2 status created in reverse order.
    await queryAsAdminWithSuccess({
      query: MUTATION_ENABLE_RFI_WORKFLOW,
      variables: {
        id: ENTITY_TYPE_CONTAINER_CASE_RFI,
        input: {
          order: 2,
          template_id: inProgressStatusId
        }
      },
    });

    await queryAsAdminWithSuccess({
      query: MUTATION_ENABLE_RFI_WORKFLOW,
      variables: {
        id: ENTITY_TYPE_CONTAINER_CASE_RFI,
        input: {
          order: 0,
          template_id: newStatusId
        }
      },
    });
    const rfiEntitySettingsWithWorkflow = await queryAsAdminWithSuccess({
      query: QUERY_REQUEST_ACCESS_SETTINGS,
      variables: { id: ENTITY_TYPE_CONTAINER_CASE_RFI },
    });

    expect(rfiEntitySettingsWithWorkflow?.data?.subType.workflowEnabled).toBeTruthy();
    expect(rfiEntitySettingsWithWorkflow?.data?.subType.statuses.length).toBe(2);
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

  it('should retrieve the created Case RFI with correct participant and objects', async () => {
    const queryResult = await queryAsAdminWithSuccess({
      query: READ_RFI_QUERY,
      variables: { id: caseRfiIdForApproval },
    });
    const caseRequestForInformation = await findRFIById(testContext, ADMIN_USER, caseRfiIdForApproval);
    logApp.info('ANGIE caseRequestForInformation', { caseRequestForInformation });
    expect(queryResult?.data?.caseRfi).not.toBeNull();
    expect(queryResult?.data?.caseRfi.id).toEqual(caseRequestForInformation.id);
    expect(queryResult?.data?.caseRfi.name).toContain(caseRequestForInformation.name);
    expect(caseRequestForInformation.object).toEqual([malwareId]);
    // TODO verify that authorized member are set

    const action: RequestAccessAction = JSON.parse(caseRequestForInformation.x_opencti_request_access);
    expect(action.status).toBe(ActionStatus.New);
    expect(action.workflowMapping).toBeDefined();
    expect(action.workflowMapping.length).toBe(3); // Status for NEW, Approved and Declined.
  });

  it.todo('should accept the created Case RFI first time be ok', async () => {
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR.client, {
      query: APPROVE_RFI_QUERY,
      variables: { id: caseRfiIdForApproval },
    });
    expect(queryResult?.data?.requestAccessValidate.action_status).toBe(ActionStatus.Approved);
    expect(queryResult?.data?.requestAccessValidate.action_executed).toBeTruthy();

    const caseRFIAccepted = await findRFIById(testContext, ADMIN_USER, caseRfiIdForApproval);
    logApp.info('ANGIE caseRFIAccepted', { caseRFIAccepted });
    const action: RequestAccessAction = JSON.parse(caseRFIAccepted.x_opencti_request_access);
    expect(action.status).toBe(ActionStatus.Approved);
  });

  it.todo('should accept the created Case RFI second time be ok too', async () => {
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR.client, {
      query: APPROVE_RFI_QUERY,
      variables: { id: caseRfiIdForApproval },
    });
    expect(queryResult?.data?.requestAccessValidate.action_status).toBe(ActionStatus.Approved);
    expect(queryResult?.data?.requestAccessValidate.action_executed).toBeTruthy();
  });

  it.todo('should create a new Request Access and associated Case RFI (For reject use case)', async () => {
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

  it.todo('should reject the created Case RFI first time be ok', async () => {
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR.client, {
      query: DECLINE_RFI_QUERY,
      variables: { id: caseRfiIdForReject },
    });
    expect(queryResult?.data?.requestAccessReject.action_status).toBe(ActionStatus.Declined);
    expect(queryResult?.data?.requestAccessReject.action_executed).toBeTruthy();

    const caseRFIAccepted = await findRFIById(testContext, ADMIN_USER, caseRfiIdForReject);
    const action: RequestAccessAction = JSON.parse(caseRFIAccepted.x_opencti_request_access);
    expect(action.status).toBe(ActionStatus.Declined);
  });

  it.todo('should reject the created Case RFI second time be ok too', async () => {
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR.client, {
      query: DECLINE_RFI_QUERY,
      variables: { input: { id: caseRfiIdForReject }, id: caseRfiIdForReject },
    });
    expect(queryResult?.data?.requestAccessReject.action_status).toBe(ActionStatus.Declined);
    expect(queryResult?.data?.requestAccessReject.action_executed).toBeTruthy();
  });

  it.todo('should be ok to accept the Case RFI when already rejected', async () => {
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR.client, {
      query: APPROVE_RFI_QUERY,
      variables: { input: { id: caseRfiIdForReject }, id: caseRfiIdForReject },
    });
    expect(queryResult?.data?.requestAccessValidate.action_status).toBe(ActionStatus.Approved);
    expect(queryResult?.data?.requestAccessValidate.action_executed).toBeTruthy();
  });

  it.todo('remove workflow configuration', async () => {

  });

  it('should remove platform organization and test data', async () => {
    await internalDeleteElementById(testContext, ADMIN_USER, malwareId);
    await internalDeleteElementById(testContext, ADMIN_USER, caseRfiIdForApproval);
    // await internalDeleteElementById(testContext, ADMIN_USER, caseRfiIdForReject);
    await enableCEAndUnSetOrganization();
  });
});

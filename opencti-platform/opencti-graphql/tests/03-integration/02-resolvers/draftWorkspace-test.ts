import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import Upload from 'graphql-upload/Upload.mjs';
import {
  ADMIN_USER,
  testContext,
  TEST_ORGANIZATION,
  USER_EDITOR,
  USER_PARTICIPATE,
  getUserIdByEmail,
  getOrganizationIdByName,
  queryInitPlatformAsAdmin,
  buildStandardUser,
} from '../../utils/testQuery';
import { queryAsAdmin, queryAsAuthUser } from '../../utils/testQueryHelper';
import { resolveUserById } from '../../../src/domain/user';
import type { AuthUser } from '../../../src/types/user';
import { MARKING_TLP_GREEN, MARKING_TLP_RED } from '../../../src/schema/identifier';
import { buildDraftValidationBundle } from '../../../src/modules/draftWorkspace/draftWorkspace-domain';
import { DRAFT_VALIDATION_CONNECTOR_ID } from '../../../src/modules/draftWorkspace/draftWorkspace-connector';
import { fileToReadStream } from '../../../src/database/file-storage';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';
import { DRAFT_STATUS_OPEN, DRAFT_STATUS_VALIDATED } from '../../../src/modules/draftWorkspace/draftStatuses';
import { WORKFLOW_INSTANCE_STATUS_FILTER } from '../../../src/utils/filtering/filtering-constants';

const CREATE_DRAFT_WORKSPACE_QUERY = gql`
    mutation DraftWorkspaceAdd($input: DraftWorkspaceAddInput!) {
        draftWorkspaceAdd(input: $input) {
            id
            standard_id
            entity_id
            name
            draft_status
            created_at
            validationWork {
                id
            }
        }
    }
`;

const DELETE_DRAFT_WORKSPACE_QUERY = gql`
    mutation DraftWorkspaceDelete($id: ID!) {
        draftWorkspaceDelete(id: $id)
    }
`;

const VALIDATE_DRAFT_WORKSPACE_QUERY = gql`
    mutation DraftWorkspaceValidate($id: ID!) {
        draftWorkspaceValidate(id: $id) {
            id
            name
            connector {
                id
            }
        }
    }
`;

const READ_DRAFT_WORKSPACE_QUERY = gql`
    query DraftWorkspace($id: String!) {
        draftWorkspace(id: $id) {
            id
            name
            entity_id
            draft_status
            created_at
            validationWork {
                id
            }
        }
    }
`;
const LIST_DRAFT_WORKSPACES_QUERY = gql`
    query DraftWorkspaces(
        $first: Int
        $after: ID
        $orderBy: DraftWorkspacesOrdering
        $orderMode: OrderingMode
        $filters: FilterGroup
        $search: String
    ) {
        draftWorkspaces(
            first: $first
            after: $after
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
            search: $search
        ) {
            edges {
                node {
                    id
                    name
                    entity_id
                    draft_status
                    created_at
                    validationWork {
                        id
                    }
                }
            }
        }
    }
`;

const READ_ME_USER_DRAFT_WORKSPACE_QUERY = gql`
    query MeUserRead {
        me {
            draftContext{
                id
                name
            }
        }
    }
`;

const MODIFY_USER_DRAFT_WORKSPACE_QUERY = gql`
    mutation MeUserWorkspaceModify($input: [EditInput]!) {
        meEdit(input: $input) {
            id
            draftContext{
                id
                name
            }
        }
    }
`;

const CREATE_REPORT_QUERY = gql`
    mutation ReportAdd($input: ReportAddInput!) {
        reportAdd(input: $input) {
            id
            standard_id
        }
    }
`;

const READ_REPORT_QUERY = gql`
    query report($id: String!) {
        report(id: $id) {
            id
            name
            description
            importFiles{
                edges {
                    node{
                        id
                        objectMarking {
                            standard_id
                        }
                        metaData {
                            description
                        }
                    }
                }
            }
        }
    }
`;

const UPDATE_REPORT_QUERY = gql`
    mutation ReportEdit($id: ID!, $input: [EditInput]!) {
        reportEdit(id: $id) {
            fieldPatch(input: $input) {
                id
                description
            }
        }
    }
`;

const DELETE_REPORT_QUERY = gql`
    mutation reportDelete($id: ID!) {
        reportEdit(id: $id) {
            delete
        }
    }
`;

const REMOVE_STIX_CORE_OBJECT_FROM_DRAFT_QUERY = gql`
    mutation StixCoreObjectEdit($id: ID!) {
        stixCoreObjectEdit(id: $id) {
            removeFromDraft
        }
    }
`;

const REMOVE_STIX_CORE_RELATIONSHIP_FROM_DRAFT_QUERY = gql`
    mutation StixCoreRelationshipEditRemoveFromDraft($id: ID!) {
        stixCoreRelationshipEdit(id: $id) {
            removeFromDraft
        }
    }
`;

const CREATE_CORE_RELATIONSHIP_QUERY = gql`
    mutation StixCoreRelationshipAddForDraftTest($input: StixCoreRelationshipAddInput!) {
        stixCoreRelationshipAdd(input: $input) {
            id
            standard_id
        }
    }
`;

const READ_REPORT_DRAFT_VERSION_QUERY = gql`
    query reportDraftVersion($id: String!) {
        report(id: $id) {
            id
            description
            draftVersion {
                draft_id
                draft_operation
            }
        }
    }
`;

const IMPORT_FILE_QUERY = gql`
    mutation StixDomainObjectImportPush($id: ID!, $file: Upload!, $fileMarkings: [String]) {
        stixDomainObjectEdit(id: $id) {
            importPush(file: $file, fileMarkings: $fileMarkings) {
                id
            }
        }
    }
`;

const DRAFT_WORKSPACE_RELATION_ADD_QUERY = gql`
  mutation DraftWorkspaceRelationAdd($id: ID!, $input: InternalRelationshipAddInput!) {
    draftWorkspaceEdit(id: $id) {
      relationAdd(input: $input) {
        id
        from {
          ... on DraftWorkspace {
            id
            objectAssignee {
              id
            }
            objectParticipant {
              id
            }
            createdBy {
              ... on Identity {
                id
              }
            }
          }
        }
      }
    }
  }
`;

const DRAFT_WORKSPACE_RELATION_DELETE_QUERY = gql`
  mutation DraftWorkspaceRelationDelete($id: ID!, $toId: StixRef!, $relationship_type: String!) {
    draftWorkspaceEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        id
        objectAssignee {
          id
        }
        objectParticipant {
          id
        }
        createdBy {
          ... on Identity {
            id
          }
        }
      }
    }
  }
`;

const DRAFT_WORKSPACE_FIELD_PATCH_QUERY = gql`
  mutation DraftWorkspaceFieldPatch($id: ID!, $input: [EditInput!]!) {
    draftWorkspaceFieldPatch(id: $id, input: $input) {
      id
      name
      description
      createdBy {
        ... on Identity {
          id
        }
      }
    }
  }
`;

const READ_DRAFT_WORKSPACE_FULL_QUERY = gql`
  query DraftWorkspaceFull($id: String!) {
    draftWorkspace(id: $id) {
      id
      name
      description
      draft_status
      objectAssignee {
        id
      }
      objectParticipant {
        id
      }
      createdBy {
        ... on Identity {
          id
        }
      }
    }
  }
`;

const modifyAdminDraftContext = async (draftId: string) => {
  const meUserModifyResult = await queryInitPlatformAsAdmin(
    MODIFY_USER_DRAFT_WORKSPACE_QUERY,
    { input: { key: 'draft_context', value: draftId } },
  );
  if (draftId) {
    expect(meUserModifyResult.data?.meEdit.draftContext.id).toEqual(draftId);
  } else {
    expect(meUserModifyResult.data?.meEdit.draftContext).toBeNull();
  }
};

describe('Drafts workspace resolver testing', () => {
  let addedDraftId = '';
  let addedDraftName = '';
  let addedDraftEntityId = '';
  let userParticipateId = '';
  let testOrganizationId = '';

  it('should create a draft', async () => {
    userParticipateId = await getUserIdByEmail(USER_PARTICIPATE.email);
    testOrganizationId = await getOrganizationIdByName(TEST_ORGANIZATION.name);
    const draftName = 'testDraft';
    const draftEntityId = 'testId';
    const createdDraft = await queryAsAdmin({
      query: CREATE_DRAFT_WORKSPACE_QUERY,
      variables: { input: { name: draftName, entity_id: draftEntityId } },
    });

    expect(createdDraft.data?.draftWorkspaceAdd).toBeDefined();
    expect(createdDraft.data?.draftWorkspaceAdd.name).toEqual(draftName);
    expect(createdDraft.data?.draftWorkspaceAdd.entity_id).toEqual(draftEntityId);
    expect(createdDraft.data?.draftWorkspaceAdd.draft_status).toEqual(DRAFT_STATUS_OPEN);
    addedDraftId = createdDraft.data?.draftWorkspaceAdd.id;
    addedDraftName = createdDraft.data?.draftWorkspaceAdd.name;
    addedDraftEntityId = createdDraft.data?.draftWorkspaceAdd.entity_id;
  });

  it('should retrieve a draft by internal id', async () => {
    const draftWorkspaceResult = await queryAsAdmin({
      query: READ_DRAFT_WORKSPACE_QUERY,
      variables: { id: addedDraftId },
    });

    expect(draftWorkspaceResult.data?.draftWorkspace).toBeDefined();
    expect(draftWorkspaceResult.data?.draftWorkspace.name).toEqual(addedDraftName);
    expect(draftWorkspaceResult.data?.draftWorkspace.entity_id).toEqual(addedDraftEntityId);
  });

  it('should list drafts without filters', async () => {
    const result = await queryAsAdmin({
      query: LIST_DRAFT_WORKSPACES_QUERY,
      variables: { first: 5 },
    });
    const drafts = result.data?.draftWorkspaces.edges;
    expect(drafts).toBeDefined();
    const draft = drafts ? drafts[0].node : undefined;

    expect(drafts.length).toEqual(1);
    expect(draft).toBeDefined();
    expect(draft.name).toEqual(addedDraftName);
  });

  it('should list draft with correct filter', async () => {
    const filters = {
      mode: 'and',
      filters: [{
        key: 'entity_id',
        operator: 'eq',
        values: [addedDraftEntityId],
        mode: 'or',
      }],
      filterGroups: [],
    };
    const result = await queryAsAdmin({
      query: LIST_DRAFT_WORKSPACES_QUERY,
      variables: { first: 5, filters },
    });
    const drafts = result.data?.draftWorkspaces.edges;
    expect(drafts).toBeDefined();
    const draft = drafts ? drafts[0].node : undefined;

    expect(drafts.length).toEqual(1);
    expect(draft).toBeDefined();
    expect(draft.name).toEqual(addedDraftName);
  });

  it('should not list draft with incorrect filter', async () => {
    const filters = {
      mode: 'and',
      filters: [{
        key: 'entity_id',
        operator: 'eq',
        values: ['incorrectId'],
        mode: 'or',
      }],
      filterGroups: [],
    };
    const result = await queryAsAdmin({
      query: LIST_DRAFT_WORKSPACES_QUERY,
      variables: { first: 5, filters },
    });
    const drafts = result.data?.draftWorkspaces.edges;
    expect(drafts).toBeDefined();
    expect(drafts.length).toEqual(0);
  });

  it('should list drafts ordered by createdBy without error', async () => {
    const result = await queryAsAdmin({
      query: LIST_DRAFT_WORKSPACES_QUERY,
      variables: { first: 5, orderBy: 'createdBy', orderMode: 'asc' },
    });
    expect(result.errors).toBeUndefined();
    expect(result.data?.draftWorkspaces.edges).toBeDefined();
  });

  it('should list drafts ordered by objectAssignee without error', async () => {
    const result = await queryAsAdmin({
      query: LIST_DRAFT_WORKSPACES_QUERY,
      variables: { first: 5, orderBy: 'objectAssignee', orderMode: 'asc' },
    });
    expect(result.errors).toBeUndefined();
    expect(result.data?.draftWorkspaces.edges).toBeDefined();
  });

  it('should list drafts ordered by objectParticipant without error', async () => {
    const result = await queryAsAdmin({
      query: LIST_DRAFT_WORKSPACES_QUERY,
      variables: { first: 5, orderBy: 'objectParticipant', orderMode: 'asc' },
    });
    expect(result.errors).toBeUndefined();
    expect(result.data?.draftWorkspaces.edges).toBeDefined();
  });

  // create entity in draft context and verify that entity doesn't exist in live context
  it('create entity in draft context', async () => {
    await modifyAdminDraftContext(addedDraftId);

    const REPORT_TO_CREATE = {
      input: {
        name: 'Report for draft',
        description: 'Report for draft',
        published: '2020-02-26T00:51:35.000Z',
        confidence: 90,
        objectMarking: [MARKING_TLP_RED],
      },
    };

    const report = await queryInitPlatformAsAdmin(CREATE_REPORT_QUERY, REPORT_TO_CREATE);
    const reportInternalId = report.data?.reportAdd.id;

    const getReportInDraftQuery = await queryInitPlatformAsAdmin(READ_REPORT_QUERY, { id: reportInternalId });
    expect(getReportInDraftQuery.data?.report.id).toBe(reportInternalId);

    await modifyAdminDraftContext('');
    const getReportOutOfDraftQuery = await queryInitPlatformAsAdmin(READ_REPORT_QUERY, { id: reportInternalId });
    expect(getReportOutOfDraftQuery.data?.report).toBeNull();
  });

  it('should add a file on stixDomainObject in draft', async () => {
    await modifyAdminDraftContext(addedDraftId);
    // Start by creating a report in draft
    const REPORT_TO_CREATE = {
      input: {
        name: 'Report for draft file',
        description: 'Report for draft file',
        published: '2020-02-26T00:51:35.000Z',
        confidence: 90,
        objectMarking: [],
      },
    };
    const report = await queryInitPlatformAsAdmin(CREATE_REPORT_QUERY, REPORT_TO_CREATE);
    const reportInternalId = report.data?.reportAdd.id;

    // Add a file to stixDomainObject with importPush
    const readStream = fileToReadStream('./tests/data/', 'test-file-to-index.txt', 'test-file-to-index.txt', 'text/plain');
    const fileUpload = { ...readStream, encoding: 'utf8' };
    const upload = new Upload();
    upload.promise = new Promise((executor) => {
      executor(fileUpload);
    });
    upload.file = fileUpload;
    const importPushQueryResult = await queryAsAdmin({
      query: IMPORT_FILE_QUERY,
      variables: { id: reportInternalId, file: upload, fileMarkings: [MARKING_TLP_GREEN] },
    }, addedDraftId);
    expect(importPushQueryResult?.data?.stixDomainObjectEdit.importPush.id).toBeDefined();
  });

  // modify live entity in draft context and verify that modification doesn't exist in live context
  it('modify live entity in draft context', async () => {
    const liveDescription = 'Report for live';
    const draftDescription = 'Report for live modified in draft';
    const LIVE_REPORT_TO_CREATE = {
      input: {
        name: liveDescription,
        description: liveDescription,
        published: '2020-02-26T00:51:35.000Z',
      },
    };

    await modifyAdminDraftContext('');
    const report = await queryInitPlatformAsAdmin(CREATE_REPORT_QUERY, LIVE_REPORT_TO_CREATE);
    const reportInternalId = report.data?.reportAdd.id;

    await modifyAdminDraftContext(addedDraftId);
    await queryInitPlatformAsAdmin(
      UPDATE_REPORT_QUERY,
      { id: reportInternalId, input: { key: 'description', value: draftDescription } },
    );
    const getReportInDraftQuery = await queryInitPlatformAsAdmin(READ_REPORT_QUERY, { id: reportInternalId });
    expect(getReportInDraftQuery.data?.report.id).toBe(reportInternalId);
    expect(getReportInDraftQuery.data?.report.description).toBe(draftDescription);

    await modifyAdminDraftContext('');
    const getReportOutOfDraftQuery = await queryInitPlatformAsAdmin(READ_REPORT_QUERY, { id: reportInternalId });
    expect(getReportOutOfDraftQuery.data?.report.id).toBe(reportInternalId);
    expect(getReportOutOfDraftQuery.data?.report.description).toBe(liveDescription);

    await queryInitPlatformAsAdmin(
      DELETE_REPORT_QUERY,
      { id: reportInternalId },
    );
  });

  it('should delete a draft by its ID', async () => {
    const deleteResult = await queryAsAdmin({
      query: DELETE_DRAFT_WORKSPACE_QUERY,
      variables: { id: addedDraftId },
    });

    const { data } = await queryAsAdmin({
      query: LIST_DRAFT_WORKSPACES_QUERY,
    });
    const drafts = data?.draftWorkspaces.edges;

    expect(deleteResult.data?.draftWorkspaceDelete).toBeDefined();
    expect(deleteResult.data?.draftWorkspaceDelete).toEqual(addedDraftId);
    expect(drafts.length).toEqual(0);
  });

  it('should validate a draft and get a correct bundle', async () => {
    // Create a draft
    const draftName = 'validationTestDraft';
    const createdDraft = await queryAsAdmin({
      query: CREATE_DRAFT_WORKSPACE_QUERY,
      variables: { input: { name: draftName } },
    });
    expect(createdDraft.data?.draftWorkspaceAdd).toBeDefined();
    addedDraftId = createdDraft.data?.draftWorkspaceAdd.id;
    addedDraftName = createdDraft.data?.draftWorkspaceAdd.name;
    await modifyAdminDraftContext(addedDraftId);

    // Create a report in the draft
    const REPORT_TO_CREATE = {
      input: {
        name: 'Report for validation draft',
        description: 'Report for validation draft',
        published: '2020-02-26T00:51:35.000Z',
        confidence: 90,
      },
    };
    const report = await queryInitPlatformAsAdmin(CREATE_REPORT_QUERY, REPORT_TO_CREATE);
    const reportStandardId = report.data?.reportAdd.standard_id;

    // Add a file to report
    const readStream = fileToReadStream('./tests/data/', 'test-file-to-index.txt', 'test-file-to-index.txt', 'text/plain');
    const fileUpload = { ...readStream, encoding: 'utf8' };
    const upload = new Upload();
    upload.promise = new Promise((executor) => {
      executor(fileUpload);
    });
    upload.file = fileUpload;
    await queryAsAdmin({
      query: IMPORT_FILE_QUERY,
      variables: { id: reportStandardId, file: upload, fileMarkings: [MARKING_TLP_GREEN] },
    }, addedDraftId);

    // Verify that validation bundle contains report
    const bundleData = await buildDraftValidationBundle(testContext, ADMIN_USER, addedDraftId);
    expect(bundleData.objects.length).toEqual(1);
    expect(bundleData.objects[0].id).toEqual(reportStandardId);
    expect(bundleData.objects[0].extensions[STIX_EXT_OCTI].files.length).toBe(1);
    expect(bundleData.objects[0].extensions[STIX_EXT_OCTI].files[0].data).toBeDefined();

    // Validate draft, verify work result and that draft was correctly deleted
    const validateResult = await queryInitPlatformAsAdmin(
      VALIDATE_DRAFT_WORKSPACE_QUERY,
      { id: addedDraftId },
    );
    expect(validateResult.data?.draftWorkspaceValidate).toBeDefined();
    expect(validateResult.data?.draftWorkspaceValidate.name).toEqual(`Draft validation ${addedDraftName} (${addedDraftId})`);
    expect(validateResult.data?.draftWorkspaceValidate.connector.id).toEqual(DRAFT_VALIDATION_CONNECTOR_ID);

    // Verify that draft still exists, but that the draft is in validated state.
    const draftWorkspaceResult = await queryInitPlatformAsAdmin(
      READ_DRAFT_WORKSPACE_QUERY,
      { id: addedDraftId },
    );

    expect(draftWorkspaceResult.data?.draftWorkspace).toBeDefined();
    expect(draftWorkspaceResult.data?.draftWorkspace.draft_status).toEqual(DRAFT_STATUS_VALIDATED);

    // Verify that me user has been moved outside of draft, and that me user can't move back into a draft in a validated state
    const meUserResult = await queryInitPlatformAsAdmin(READ_ME_USER_DRAFT_WORKSPACE_QUERY);
    expect(meUserResult.data?.me.draftContext).toBeNull();
    const meUserModifyResult = await queryInitPlatformAsAdmin(
      MODIFY_USER_DRAFT_WORKSPACE_QUERY,
      { input: { key: 'draft_context', value: addedDraftId } },
    );
    expect(meUserModifyResult.errors).toBeDefined();
  });

  it('should be able to remove created entities from draft', async () => {
    // Create a draft
    const draftName = 'entityRemovalTestDraft';
    const createdDraft = await queryAsAdmin({
      query: CREATE_DRAFT_WORKSPACE_QUERY,
      variables: { input: { name: draftName } },
    });
    expect(createdDraft.data?.draftWorkspaceAdd).toBeDefined();
    addedDraftId = createdDraft.data?.draftWorkspaceAdd.id;
    addedDraftName = createdDraft.data?.draftWorkspaceAdd.name;
    await modifyAdminDraftContext(addedDraftId);

    // Verify that report created in draft is removed
    const REPORT_TO_CREATE = {
      input: {
        name: 'Report for removal draft',
        description: 'Report for removal draft',
        published: '2020-02-26T00:51:35.000Z',
        confidence: 90,
      },
    };
    const report = await queryInitPlatformAsAdmin(CREATE_REPORT_QUERY, REPORT_TO_CREATE);
    const reportStandardId = report.data?.reportAdd.standard_id;
    await queryInitPlatformAsAdmin(REMOVE_STIX_CORE_OBJECT_FROM_DRAFT_QUERY, { id: reportStandardId });
    const getRemovedCreatedReportQuery = await queryInitPlatformAsAdmin(READ_REPORT_QUERY, { id: reportStandardId });
    expect(getRemovedCreatedReportQuery.data?.report).toBeNull();

    // Verify that report updated in draft is removed and reverted to live version
    const originalDescription = 'Report for update removal draft';
    const updateDescription = 'Updated draft desc';
    await modifyAdminDraftContext('');
    const REPORT_TO_UPDATE = {
      input: {
        name: 'Report for update removal draft',
        description: originalDescription,
        published: '2020-02-26T00:51:35.000Z',
        confidence: 90,
      },
    };
    const reportToUpdate = await queryInitPlatformAsAdmin(CREATE_REPORT_QUERY, REPORT_TO_UPDATE);
    const reportToUpdateStandardId = reportToUpdate.data?.reportAdd.standard_id;

    await modifyAdminDraftContext(addedDraftId);
    await queryInitPlatformAsAdmin(
      UPDATE_REPORT_QUERY,
      { id: reportToUpdateStandardId, input: { key: 'description', value: updateDescription } },
    );
    await queryInitPlatformAsAdmin(REMOVE_STIX_CORE_OBJECT_FROM_DRAFT_QUERY, { id: reportToUpdateStandardId });
    const reportAfterRemoval = await queryInitPlatformAsAdmin(READ_REPORT_QUERY, { id: reportToUpdateStandardId });
    expect(reportAfterRemoval.data?.report.description).toBe(originalDescription);
    await modifyAdminDraftContext('');
    await queryInitPlatformAsAdmin(
      DELETE_REPORT_QUERY,
      { id: reportToUpdateStandardId },
    );

    // Verify that report deleted in draft is removed and reverted to live version
    const REPORT_TO_DELETE = {
      input: {
        name: 'Report to delete in draft',
        description: 'Report to delete in draft',
        published: '2020-02-26T00:51:35.000Z',
        confidence: 90,
      },
    };
    const reportToDelete = await queryInitPlatformAsAdmin(CREATE_REPORT_QUERY, REPORT_TO_DELETE);
    const reportToDeleteStandardId = reportToDelete.data?.reportAdd.standard_id;

    await modifyAdminDraftContext(addedDraftId);
    await queryInitPlatformAsAdmin(
      DELETE_REPORT_QUERY,
      { id: reportToDeleteStandardId },
    );
    const getReportDeletedQuery = await queryInitPlatformAsAdmin(READ_REPORT_QUERY, { id: reportToDeleteStandardId });
    expect(getReportDeletedQuery.data?.report).toBeNull();
    await queryInitPlatformAsAdmin(REMOVE_STIX_CORE_OBJECT_FROM_DRAFT_QUERY, { id: reportToDeleteStandardId });
    const reportAfterDeleteRemoval = await queryInitPlatformAsAdmin(READ_REPORT_QUERY, { id: reportToDeleteStandardId });
    expect(reportAfterDeleteRemoval.data?.report).toBeDefined();
    await modifyAdminDraftContext('');
    await queryInitPlatformAsAdmin(
      DELETE_REPORT_QUERY,
      { id: reportToDeleteStandardId },
    );
  });

  it('should remove an update_linked entity from draft once its linking relation is gone (issue #17256)', async () => {
    // Create a draft
    const draftName = 'updateLinkedRemovalTestDraft';
    const createdDraft = await queryAsAdmin({
      query: CREATE_DRAFT_WORKSPACE_QUERY,
      variables: { input: { name: draftName } },
    });
    expect(createdDraft.data?.draftWorkspaceAdd).toBeDefined();
    const updateLinkedDraftId = createdDraft.data?.draftWorkspaceAdd.id;

    // Ensure we are not already in a draft context left over from a previous test before
    // creating the "live" report below.
    await modifyAdminDraftContext('');

    // Create a report live (outside of any draft)
    const EXISTING_REPORT = {
      input: {
        name: 'Existing report for update_linked test',
        description: 'Original description',
        published: '2020-02-26T00:51:35.000Z',
        confidence: 90,
      },
    };
    const existingReport = await queryInitPlatformAsAdmin(CREATE_REPORT_QUERY, EXISTING_REPORT);
    const existingReportStandardId = existingReport.data?.reportAdd.standard_id;
    const existingReportId = existingReport.data?.reportAdd.id;

    await modifyAdminDraftContext(updateLinkedDraftId);

    // Update the pre-existing report in draft (draft_operation: update)
    await queryInitPlatformAsAdmin(
      UPDATE_REPORT_QUERY,
      { id: existingReportStandardId, input: { key: 'description', value: 'Updated in draft' } },
    );

    // Create a new report in draft and link it to the existing report (draft_operation: create relation)
    const NEW_REPORT_IN_DRAFT = {
      input: {
        name: 'New report created in draft',
        description: 'New report created in draft',
        published: '2020-02-26T00:51:35.000Z',
        confidence: 90,
      },
    };
    const newReportInDraft = await queryInitPlatformAsAdmin(CREATE_REPORT_QUERY, NEW_REPORT_IN_DRAFT);
    const newReportInDraftId = newReportInDraft.data?.reportAdd.id;

    const createdRelation = await queryInitPlatformAsAdmin(CREATE_CORE_RELATIONSHIP_QUERY, {
      input: {
        fromId: newReportInDraftId,
        toId: existingReportId,
        relationship_type: 'related-to',
      },
    });
    const createdRelationStandardId = createdRelation.data?.stixCoreRelationshipAdd.standard_id;
    expect(createdRelationStandardId).toBeDefined();

    // Removing the existing report from draft should revert its own field changes but keep it
    // as update_linked, since the draft-created relation still targets it.
    await queryInitPlatformAsAdmin(REMOVE_STIX_CORE_OBJECT_FROM_DRAFT_QUERY, { id: existingReportStandardId });
    const reportAfterFirstRemoval = await queryInitPlatformAsAdmin(READ_REPORT_DRAFT_VERSION_QUERY, { id: existingReportStandardId });
    expect(reportAfterFirstRemoval.data?.report.description).toBe('Original description');
    expect(reportAfterFirstRemoval.data?.report.draftVersion?.draft_operation).toBe('update_linked');

    // Calling remove from draft again while still update_linked must not throw and must be a no-op
    await queryInitPlatformAsAdmin(REMOVE_STIX_CORE_OBJECT_FROM_DRAFT_QUERY, { id: existingReportStandardId });
    const reportStillLinked = await queryInitPlatformAsAdmin(READ_REPORT_DRAFT_VERSION_QUERY, { id: existingReportStandardId });
    expect(reportStillLinked.data?.report.draftVersion?.draft_operation).toBe('update_linked');

    // Removing the linking relation from draft should now cascade-clean the update_linked report
    await queryInitPlatformAsAdmin(REMOVE_STIX_CORE_RELATIONSHIP_FROM_DRAFT_QUERY, { id: createdRelationStandardId });
    const reportAfterCascadeCleanup = await queryInitPlatformAsAdmin(READ_REPORT_DRAFT_VERSION_QUERY, { id: existingReportStandardId });
    expect(reportAfterCascadeCleanup.data?.report.draftVersion).toBeNull();

    await modifyAdminDraftContext('');
    await queryInitPlatformAsAdmin(DELETE_REPORT_QUERY, { id: existingReportStandardId });
    await queryAsAdmin({ query: DELETE_DRAFT_WORKSPACE_QUERY, variables: { id: updateLinkedDraftId } });
  });

  // ---- Tests for draftWorkspaceEditField ----
  describe('draftWorkspaceEditField', () => {
    let fieldPatchDraftId = '';

    it('should create a draft for field patch tests', async () => {
      const createdDraft = await queryAsAdmin({
        query: CREATE_DRAFT_WORKSPACE_QUERY,
        variables: { input: { name: 'fieldPatchTestDraft' } },
      });
      expect(createdDraft.data?.draftWorkspaceAdd).toBeDefined();
      fieldPatchDraftId = createdDraft.data?.draftWorkspaceAdd.id;
    });

    it('should update the name of a draft', async () => {
      const newName = 'Updated Draft Name';
      const result = await queryAsAdmin({
        query: DRAFT_WORKSPACE_FIELD_PATCH_QUERY,
        variables: {
          id: fieldPatchDraftId,
          input: [{ key: 'name', value: [newName] }],
        },
      });
      expect(result.data?.draftWorkspaceFieldPatch).toBeDefined();
      expect(result.data?.draftWorkspaceFieldPatch.name).toEqual(newName);
    });

    it('should update the description of a draft', async () => {
      const newDescription = 'Updated Draft Description';
      const result = await queryAsAdmin({
        query: DRAFT_WORKSPACE_FIELD_PATCH_QUERY,
        variables: {
          id: fieldPatchDraftId,
          input: [{ key: 'description', value: [newDescription] }],
        },
      });
      expect(result.data?.draftWorkspaceFieldPatch).toBeDefined();
      expect(result.data?.draftWorkspaceFieldPatch.description).toEqual(newDescription);
    });

    it('should add a createdBy relation to a draft', async () => {
      const result = await queryAsAdmin({
        query: DRAFT_WORKSPACE_FIELD_PATCH_QUERY,
        variables: {
          id: fieldPatchDraftId,
          input: [{ key: 'createdBy', value: [testOrganizationId] }],
        },
      });
      expect(result.data?.draftWorkspaceFieldPatch).toBeDefined();
      expect(result.data?.draftWorkspaceFieldPatch.createdBy).toBeDefined();
      expect(result.data?.draftWorkspaceFieldPatch.createdBy.id).toEqual(testOrganizationId);
    });

    it('should update multiple fields at once', async () => {
      const newName = 'Multi-update Draft';
      const newDescription = 'Multi-update description';
      const result = await queryAsAdmin({
        query: DRAFT_WORKSPACE_FIELD_PATCH_QUERY,
        variables: {
          id: fieldPatchDraftId,
          input: [
            { key: 'name', value: [newName] },
            { key: 'description', value: [newDescription] },
          ],
        },
      });
      expect(result.data?.draftWorkspaceFieldPatch).toBeDefined();
      expect(result.data?.draftWorkspaceFieldPatch.name).toEqual(newName);
      expect(result.data?.draftWorkspaceFieldPatch.description).toEqual(newDescription);
    });

    it('should fail to update a non-existent draft', async () => {
      const result = await queryAsAdmin({
        query: DRAFT_WORKSPACE_FIELD_PATCH_QUERY,
        variables: {
          id: 'non-existent-draft-id',
          input: [{ key: 'name', value: ['Should fail'] }],
        },
      });
      expect(result.errors).toBeDefined();
      expect(result.errors?.length).toBeGreaterThan(0);
    });

    it('should verify updated fields persist after re-read', async () => {
      const newName = 'Persisted Name';
      await queryAsAdmin({
        query: DRAFT_WORKSPACE_FIELD_PATCH_QUERY,
        variables: {
          id: fieldPatchDraftId,
          input: [{ key: 'name', value: [newName] }],
        },
      });
      const readResult = await queryAsAdmin({
        query: READ_DRAFT_WORKSPACE_FULL_QUERY,
        variables: { id: fieldPatchDraftId },
      });
      expect(readResult.data?.draftWorkspace).toBeDefined();
      expect(readResult.data?.draftWorkspace.name).toEqual(newName);
    });

    it('should clean up field patch test draft', async () => {
      await queryAsAdmin({
        query: DELETE_DRAFT_WORKSPACE_QUERY,
        variables: { id: fieldPatchDraftId },
      });
    });
  });

  // ---- Tests for draftWorkspaceAddRelation ----
  describe('draftWorkspaceAddRelation', () => {
    let relationDraftId = '';

    it('should create a draft for relation tests', async () => {
      const createdDraft = await queryAsAdmin({
        query: CREATE_DRAFT_WORKSPACE_QUERY,
        variables: { input: { name: 'relationTestDraft' } },
      });
      expect(createdDraft.data?.draftWorkspaceAdd).toBeDefined();
      relationDraftId = createdDraft.data?.draftWorkspaceAdd.id;
    });

    it('should add an objectAssignee relation to a draft', async () => {
      const result = await queryAsAdmin({
        query: DRAFT_WORKSPACE_RELATION_ADD_QUERY,
        variables: {
          id: relationDraftId,
          input: {
            toId: userParticipateId,
            relationship_type: 'object-assignee',
          },
        },
      });
      expect(result.data?.draftWorkspaceEdit.relationAdd).toBeDefined();
      const from = result.data?.draftWorkspaceEdit.relationAdd.from;
      expect(from.objectAssignee.length).toBeGreaterThanOrEqual(1);
      const assigneeIds = from.objectAssignee.map((a: { id: string }) => a.id);
      expect(assigneeIds).toContain(userParticipateId);
    });

    it('should add an objectParticipant relation to a draft', async () => {
      const result = await queryAsAdmin({
        query: DRAFT_WORKSPACE_RELATION_ADD_QUERY,
        variables: {
          id: relationDraftId,
          input: {
            toId: userParticipateId,
            relationship_type: 'object-participant',
          },
        },
      });
      expect(result.data?.draftWorkspaceEdit.relationAdd).toBeDefined();
      const from = result.data?.draftWorkspaceEdit.relationAdd.from;
      expect(from.objectParticipant.length).toBeGreaterThanOrEqual(1);
      const participantIds = from.objectParticipant.map((p: { id: string }) => p.id);
      expect(participantIds).toContain(userParticipateId);
    });

    it('should fail to add a relation to a non-existent draft', async () => {
      const result = await queryAsAdmin({
        query: DRAFT_WORKSPACE_RELATION_ADD_QUERY,
        variables: {
          id: 'non-existent-draft-id',
          input: {
            toId: userParticipateId,
            relationship_type: 'object-assignee',
          },
        },
      });
      expect(result.errors).toBeDefined();
      expect(result.errors?.length).toBeGreaterThan(0);
    });

    it('should verify added relations persist after re-read', async () => {
      const readResult = await queryAsAdmin({
        query: READ_DRAFT_WORKSPACE_FULL_QUERY,
        variables: { id: relationDraftId },
      });
      const draft = readResult.data?.draftWorkspace;
      expect(draft).toBeDefined();
      expect(draft.objectAssignee.length).toBeGreaterThanOrEqual(1);
      expect(draft.objectParticipant.length).toBeGreaterThanOrEqual(1);
      expect(draft.createdBy).toBeDefined();
    });

    it('should clean up relation add test draft', async () => {
      await queryAsAdmin({
        query: DELETE_DRAFT_WORKSPACE_QUERY,
        variables: { id: relationDraftId },
      });
    });
  });

  // ---- Tests for draftWorkspaceDeleteRelation ----
  describe('draftWorkspaceDeleteRelation', () => {
    let deleteRelDraftId = '';

    it('should create a draft with relations for delete tests', async () => {
      const createdDraft = await queryAsAdmin({
        query: CREATE_DRAFT_WORKSPACE_QUERY,
        variables: { input: { name: 'deleteRelationTestDraft' } },
      });
      expect(createdDraft.data?.draftWorkspaceAdd).toBeDefined();
      deleteRelDraftId = createdDraft.data?.draftWorkspaceAdd.id;

      // Add objectAssignee relation
      await queryAsAdmin({
        query: DRAFT_WORKSPACE_RELATION_ADD_QUERY,
        variables: {
          id: deleteRelDraftId,
          input: {
            toId: userParticipateId,
            relationship_type: 'object-assignee',
          },
        },
      });

      // Add objectParticipant relation
      await queryAsAdmin({
        query: DRAFT_WORKSPACE_RELATION_ADD_QUERY,
        variables: {
          id: deleteRelDraftId,
          input: {
            toId: userParticipateId,
            relationship_type: 'object-participant',
          },
        },
      });

      // Verify all relations are added
      const readResult = await queryAsAdmin({
        query: READ_DRAFT_WORKSPACE_FULL_QUERY,
        variables: { id: deleteRelDraftId },
      });
      expect(readResult.data?.draftWorkspace.objectAssignee.length).toBeGreaterThanOrEqual(1);
      expect(readResult.data?.draftWorkspace.objectParticipant.length).toBeGreaterThanOrEqual(1);
    });

    it('should delete an objectAssignee relation from a draft', async () => {
      const result = await queryAsAdmin({
        query: DRAFT_WORKSPACE_RELATION_DELETE_QUERY,
        variables: {
          id: deleteRelDraftId,
          toId: userParticipateId,
          relationship_type: 'object-assignee',
        },
      });
      expect(result.data?.draftWorkspaceEdit.relationDelete).toBeDefined();
      const draft = result.data?.draftWorkspaceEdit.relationDelete;
      const assigneeIds = draft.objectAssignee.map((a: { id: string }) => a.id);
      expect(assigneeIds).not.toContain(userParticipateId);
    });

    it('should delete an objectParticipant relation from a draft', async () => {
      const result = await queryAsAdmin({
        query: DRAFT_WORKSPACE_RELATION_DELETE_QUERY,
        variables: {
          id: deleteRelDraftId,
          toId: userParticipateId,
          relationship_type: 'object-participant',
        },
      });
      expect(result.data?.draftWorkspaceEdit.relationDelete).toBeDefined();
      const draft = result.data?.draftWorkspaceEdit.relationDelete;
      const participantIds = draft.objectParticipant.map((p: { id: string }) => p.id);
      expect(participantIds).not.toContain(userParticipateId);
    });

    it('should verify relations are removed after re-read', async () => {
      const readResult = await queryAsAdmin({
        query: READ_DRAFT_WORKSPACE_FULL_QUERY,
        variables: { id: deleteRelDraftId },
      });
      const draft = readResult.data?.draftWorkspace;
      expect(draft).toBeDefined();
      expect(draft.objectAssignee.length).toEqual(0);
      expect(draft.objectParticipant.length).toEqual(0);
      expect(draft.createdBy).toBeNull();
    });

    it('should fail to delete a relation from a non-existent draft', async () => {
      const result = await queryAsAdmin({
        query: DRAFT_WORKSPACE_RELATION_DELETE_QUERY,
        variables: {
          id: 'non-existent-draft-id',
          toId: userParticipateId,
          relationship_type: 'object-assignee',
        },
      });
      expect(result.errors).toBeDefined();
      expect(result.errors?.length).toBeGreaterThan(0);
    });

    it('should clean up delete relation test draft', async () => {
      await queryAsAdmin({
        query: DELETE_DRAFT_WORKSPACE_QUERY,
        variables: { id: deleteRelDraftId },
      });
    });
  });

  describe('Draft delete access rights', () => {
    let restrictedDraftId = '';
    let userEditorId = '';
    let userParticipateId = '';

    const executeAsResolvedUserIsExpectedForbidden = async (testUser: any, request: any) => {
      const userId = await getUserIdByEmail(testUser.email);
      const user = await resolveUserById(testContext, userId);
      const authUser = {
        ...user,
        origin: { referer: 'test', user_id: user.internal_id },
      } as AuthUser;
      const queryResult = await queryAsAuthUser(authUser, request);
      expect(queryResult.errors, 'FORBIDDEN_ACCESS is expected.').toBeDefined();
      expect(queryResult.errors?.length).toBe(1);
      expect(queryResult.errors?.[0].extensions?.code).toBe('FORBIDDEN_ACCESS');
    };

    const executeAsResolvedUserWithSuccess = async (testUser: any, request: any) => {
      const userId = await getUserIdByEmail(testUser.email);
      const user = await resolveUserById(testContext, userId);
      const authUser = {
        ...user,
        origin: { referer: 'test', user_id: user.internal_id },
      } as AuthUser;
      const queryResult = await queryAsAuthUser(authUser, request);
      expect(queryResult.errors).toBeUndefined();
      expect(queryResult.data).toBeDefined();
      return queryResult;
    };

    it('should set up restricted draft for access right tests', async () => {
      userEditorId = await getUserIdByEmail(USER_EDITOR.email);
      userParticipateId = await getUserIdByEmail(USER_PARTICIPATE.email);
      // Create a draft with USER_EDITOR as view-only and USER_PARTICIPATE as edit (restricted)
      const createdDraft = await queryAsAdmin({
        query: CREATE_DRAFT_WORKSPACE_QUERY,
        variables: {
          input: {
            name: 'restrictedDraftForDeleteTests',
            authorized_members: [
              { id: userEditorId, access_right: 'view' },
              { id: userParticipateId, access_right: 'edit' },
            ],
          },
        },
      });
      expect(createdDraft.data?.draftWorkspaceAdd).toBeDefined();
      restrictedDraftId = createdDraft.data?.draftWorkspaceAdd.id;
    });

    // Rule: user with delete capability but only view on draft → cannot delete (blocked at domain level)
    it('should not allow deletion with delete capability but view-only access on draft', async () => {
      await executeAsResolvedUserIsExpectedForbidden(USER_EDITOR, {
        query: DELETE_DRAFT_WORKSPACE_QUERY,
        variables: { id: restrictedDraftId },
      });
    });

    // Rule: user with edit access on draft but without delete capability → cannot delete (blocked at GraphQL @auth level)
    it('should not allow deletion without delete capability even with edit access on draft', async () => {
      // USER_PARTICIPATE has edit access on the draft but no KNOWLEDGE_KNUPDATE_KNDELETE capability
      await executeAsResolvedUserIsExpectedForbidden(USER_PARTICIPATE, {
        query: DELETE_DRAFT_WORKSPACE_QUERY,
        variables: { id: restrictedDraftId },
      });
    });

    // Rule: user with delete capability AND edit access on draft → can delete
    it('should allow deletion with delete capability and edit access on draft', async () => {
      // Give USER_EDITOR edit access; CREATOR (admin user) keeps admin to satisfy containsValidAdmin constraint
      const editResult = await queryAsAdmin({
        query: gql`
          mutation DraftWorkspaceEditAuthorizedMembers($id: ID!, $input: [MemberAccessInput!]) {
            draftWorkspaceEditAuthorizedMembers(id: $id, input: $input) { id }
          }
        `,
        variables: {
          id: restrictedDraftId,
          input: [
            { id: 'CREATOR', access_right: 'admin' },
            { id: userEditorId, access_right: 'edit' },
          ],
        },
      });
      expect(editResult.errors, `editAuthorizedMembers failed: ${JSON.stringify(editResult.errors)}`).toBeUndefined();
      await executeAsResolvedUserWithSuccess(USER_EDITOR, {
        query: DELETE_DRAFT_WORKSPACE_QUERY,
        variables: { id: restrictedDraftId },
      });
    });
  });

  describe('draftWorkspacesNumber, draftWorkspacesTimeSeries, draftWorkspacesDistribution', () => {
    const DRAFT_WORKSPACES_NUMBER_QUERY = gql`
      query DraftWorkspacesNumber($filters: FilterGroup) {
        draftWorkspacesNumber(filters: $filters) {
          count
          total
        }
      }
    `;

    const DRAFT_WORKSPACES_TIME_SERIES_QUERY = gql`
      query DraftWorkspacesTimeSeries(
        $field: String!
        $operation: StatsOperation!
        $startDate: DateTime!
        $endDate: DateTime
        $interval: String!
        $filters: FilterGroup
      ) {
        draftWorkspacesTimeSeries(
          field: $field
          operation: $operation
          startDate: $startDate
          endDate: $endDate
          interval: $interval
          filters: $filters
        ) {
          date
          value
        }
      }
    `;

    const DRAFT_WORKSPACES_DISTRIBUTION_QUERY = gql`
      query DraftWorkspacesDistribution(
        $field: String!
        $operation: StatsOperation!
        $filters: FilterGroup
      ) {
        draftWorkspacesDistribution(
          field: $field
          operation: $operation
          filters: $filters
        ) {
          label
          value
        }
      }
    `;

    let statsDraftId = '';

    it('should create a draft for stats queries', async () => {
      const result = await queryAsAdmin({
        query: CREATE_DRAFT_WORKSPACE_QUERY,
        variables: { input: { name: 'Stats test draft', entity_id: 'stats-test-entity' } },
      });
      expect(result.errors).toBeUndefined();
      statsDraftId = result.data?.draftWorkspaceAdd.id;
      expect(statsDraftId).toBeDefined();
    });

    it('should return a number with count and total', async () => {
      const result = await queryAsAdmin({
        query: DRAFT_WORKSPACES_NUMBER_QUERY,
        variables: {},
      });
      expect(result.errors).toBeUndefined();
      expect(result.data?.draftWorkspacesNumber).toBeDefined();
      expect(result.data?.draftWorkspacesNumber.total).toBeGreaterThanOrEqual(1);
      expect(result.data?.draftWorkspacesNumber.count).toBeGreaterThanOrEqual(0);
    });

    it('should return a number filtered by entity_type=DraftWorkspace', async () => {
      const result = await queryAsAdmin({
        query: DRAFT_WORKSPACES_NUMBER_QUERY,
        variables: {
          filters: {
            mode: 'and',
            filters: [{ key: 'entity_type', values: ['DraftWorkspace'], operator: 'eq', mode: 'or' }],
            filterGroups: [],
          },
        },
      });
      expect(result.errors).toBeUndefined();
      expect(result.data?.draftWorkspacesNumber.total).toBeGreaterThanOrEqual(1);
    });

    it('should return empty count when filtering by workflowInstanceCurrentState with no matching instances', async () => {
      const result = await queryAsAdmin({
        query: DRAFT_WORKSPACES_NUMBER_QUERY,
        variables: {
          filters: {
            mode: 'and',
            filters: [{ key: WORKFLOW_INSTANCE_STATUS_FILTER, values: ['non-existent-status-template-id'], operator: 'eq', mode: 'or' }],
            filterGroups: [],
          },
        },
      });
      expect(result.errors).toBeUndefined();
      expect(result.data?.draftWorkspacesNumber.count).toEqual(0);
    });

    it('should return a time series array', async () => {
      const result = await queryAsAdmin({
        query: DRAFT_WORKSPACES_TIME_SERIES_QUERY,
        variables: {
          field: 'created_at',
          operation: 'count',
          startDate: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString(),
          endDate: new Date().toISOString(),
          interval: 'month',
        },
      });
      expect(result.errors).toBeUndefined();
      expect(Array.isArray(result.data?.draftWorkspacesTimeSeries)).toBe(true);
      const total = result.data?.draftWorkspacesTimeSeries.reduce((sum: number, entry: { value: number }) => sum + entry.value, 0);
      expect(total).toBeGreaterThanOrEqual(1);
    });

    it('should return a distribution by draft_status', async () => {
      const result = await queryAsAdmin({
        query: DRAFT_WORKSPACES_DISTRIBUTION_QUERY,
        variables: {
          field: 'draft_status',
          operation: 'count',
        },
      });
      expect(result.errors).toBeUndefined();
      expect(Array.isArray(result.data?.draftWorkspacesDistribution)).toBe(true);
      expect(result.data?.draftWorkspacesDistribution.length).toBeGreaterThanOrEqual(1);
    });

    it('should return an empty distribution when field is workflowInstanceCurrentState and no instances exist', async () => {
      const result = await queryAsAdmin({
        query: DRAFT_WORKSPACES_DISTRIBUTION_QUERY,
        variables: {
          field: WORKFLOW_INSTANCE_STATUS_FILTER,
          operation: 'count',
        },
      });
      expect(result.errors).toBeUndefined();
      expect(Array.isArray(result.data?.draftWorkspacesDistribution)).toBe(true);
    });

    it('should clean up stats test draft', async () => {
      const result = await queryAsAdmin({
        query: DELETE_DRAFT_WORKSPACE_QUERY,
        variables: { id: statsDraftId },
      });
      expect(result.errors).toBeUndefined();
    });
  });

  describe('Draft access with KNOWLEDGE_KNUPDATE capability in draft only (not in main)', () => {
    // A user who has KNOWLEDGE_KNUPDATE only in their draft capabilities (not in main capabilities).
    // This models a real-world scenario where the platform grants update rights exclusively in
    // draft contexts — the user has no edit permissions on the live platform.
    const userWithDraftCapaOnly = {
      ...buildStandardUser([], [], []),
      capabilities: [],
      capabilitiesInDraft: [{ name: 'KNOWLEDGE_KNUPDATE' }],
    };
    const userWithNoCapa = {
      ...buildStandardUser([], [], []),
      capabilities: [],
    };

    let draftCreatedByDraftUser = '';

    // The draftWorkspaceAdd mutation carries @auth(forDraft: [KNOWLEDGE_KNUPDATE]), which means
    // the platform checks capabilitiesInDraft even without an active draft_context.
    it('should allow creating a draft with KNOWLEDGE_KNUPDATE in draft capabilities only', async () => {
      const result = await queryAsAuthUser(userWithDraftCapaOnly, {
        query: CREATE_DRAFT_WORKSPACE_QUERY,
        variables: { input: { name: 'draft-created-by-draft-only-user' } },
      });
      expect(result.errors, `Unexpected errors: ${JSON.stringify(result.errors)}`).toBeUndefined();
      expect(result.data?.draftWorkspaceAdd).toBeDefined();
      expect(result.data?.draftWorkspaceAdd.draft_status).toEqual(DRAFT_STATUS_OPEN);
      draftCreatedByDraftUser = result.data?.draftWorkspaceAdd.id;
    });

    // draftWorkspacesRestricted carries @auth(for: [KNOWLEDGE]).
    // KNOWLEDGE_KNUPDATE.includes('KNOWLEDGE') is true, so when draft_context is active the user
    // passes the capability check through capabilitiesInDraft.
    it('should allow listing drafts when KNOWLEDGE_KNUPDATE is in draft capabilities and a draft context is active', async () => {
      // A pre-existing draft is needed to supply a valid draft_context.
      const setupDraft = await queryAsAdmin({
        query: CREATE_DRAFT_WORKSPACE_QUERY,
        variables: { input: { name: 'draft-context-for-list-access-test' } },
      });
      const draftContextId = setupDraft.data?.draftWorkspaceAdd.id;
      expect(draftContextId).toBeDefined();

      const userInDraftContext = {
        ...userWithDraftCapaOnly,
        draft_context: draftContextId,
      };

      const listResult = await queryAsAuthUser(userInDraftContext, {
        query: gql`
          query DraftWorkspacesRestricted {
            draftWorkspacesRestricted(first: 5) {
              edges {
                node {
                  id
                  name
                }
              }
            }
          }
        `,
      });
      expect(listResult.errors, `Unexpected errors: ${JSON.stringify(listResult.errors)}`).toBeUndefined();
      expect(listResult.data?.draftWorkspacesRestricted).toBeDefined();

      // Cleanup the setup draft
      await queryAsAdmin({ query: DELETE_DRAFT_WORKSPACE_QUERY, variables: { id: draftContextId } });
    });

    // Negative case: a user with no capabilities at all must be rejected with FORBIDDEN_ACCESS.
    it('should not allow creating a draft with no capabilities', async () => {
      const result = await queryAsAuthUser(userWithNoCapa, {
        query: CREATE_DRAFT_WORKSPACE_QUERY,
        variables: { input: { name: 'draft-should-be-forbidden' } },
      });
      expect(result.errors).toBeDefined();
      expect(result.errors?.length).toBe(1);
      expect(result.errors?.[0].extensions?.code).toBe('FORBIDDEN_ACCESS');
    });

    it('should clean up drafts created during draft-only capability tests', async () => {
      if (draftCreatedByDraftUser) {
        await queryAsAdmin({ query: DELETE_DRAFT_WORKSPACE_QUERY, variables: { id: draftCreatedByDraftUser } });
      }
    });
  });
});

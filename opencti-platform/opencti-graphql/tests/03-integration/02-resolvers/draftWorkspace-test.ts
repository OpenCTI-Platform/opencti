import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import Upload from 'graphql-upload/Upload.mjs';
import { ADMIN_USER, adminQuery, queryAsAdmin, testContext } from '../../utils/testQuery';
import { MARKING_TLP_GREEN, MARKING_TLP_RED } from '../../../src/schema/identifier';
import { buildDraftValidationBundle } from '../../../src/modules/draftWorkspace/draftWorkspace-domain';
import { DRAFT_VALIDATION_CONNECTOR_ID } from '../../../src/modules/draftWorkspace/draftWorkspace-connector';
import { fileToReadStream } from '../../../src/database/file-storage';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';
import { DRAFT_STATUS_OPEN, DRAFT_STATUS_VALIDATED } from '../../../src/modules/draftWorkspace/draftStatuses';

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

const IMPORT_FILE_QUERY = gql`
    mutation StixDomainObjectImportPush($id: ID!, $file: Upload!, $fileMarkings: [String]) {
        stixDomainObjectEdit(id: $id) {
            importPush(file: $file, fileMarkings: $fileMarkings) {
                id
            }
        }
    }
`;

const modifyAdminDraftContext = async (draftId: string) => {
  const meUserModifyResult = await adminQuery({
    query: MODIFY_USER_DRAFT_WORKSPACE_QUERY,
    variables: { input: { key: 'draft_context', value: draftId } },
  });
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

  it('should create a draft', async () => {
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
      variables: { id: addedDraftId }
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

    const report = await adminQuery({ query: CREATE_REPORT_QUERY, variables: REPORT_TO_CREATE });
    const reportInternalId = report.data.reportAdd.id;

    const getReportInDraftQuery = await adminQuery({ query: READ_REPORT_QUERY, variables: { id: reportInternalId } });
    expect(getReportInDraftQuery.data.report.id).toBe(reportInternalId);

    await modifyAdminDraftContext('');
    const getReportOutOfDraftQuery = await adminQuery({ query: READ_REPORT_QUERY, variables: { id: reportInternalId } });
    expect(getReportOutOfDraftQuery.data.report).toBeNull();
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
    const report = await adminQuery({ query: CREATE_REPORT_QUERY, variables: REPORT_TO_CREATE });
    const reportInternalId = report.data.reportAdd.id;

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
      variables: { id: reportInternalId, file: upload, fileMarkings: [MARKING_TLP_GREEN] }
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
    const report = await adminQuery({ query: CREATE_REPORT_QUERY, variables: LIVE_REPORT_TO_CREATE });
    const reportInternalId = report.data.reportAdd.id;

    await modifyAdminDraftContext(addedDraftId);
    await adminQuery({
      query: UPDATE_REPORT_QUERY,
      variables: { id: reportInternalId, input: { key: 'description', value: draftDescription } },
    });
    const getReportInDraftQuery = await adminQuery({ query: READ_REPORT_QUERY, variables: { id: reportInternalId } });
    expect(getReportInDraftQuery.data.report.id).toBe(reportInternalId);
    expect(getReportInDraftQuery.data.report.description).toBe(draftDescription);

    await modifyAdminDraftContext('');
    const getReportOutOfDraftQuery = await adminQuery({ query: READ_REPORT_QUERY, variables: { id: reportInternalId } });
    expect(getReportOutOfDraftQuery.data.report.id).toBe(reportInternalId);
    expect(getReportOutOfDraftQuery.data.report.description).toBe(liveDescription);

    await adminQuery({
      query: DELETE_REPORT_QUERY,
      variables: { id: reportInternalId },
    });
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
    const report = await adminQuery({ query: CREATE_REPORT_QUERY, variables: REPORT_TO_CREATE });
    const reportStandardId = report.data.reportAdd.standard_id;

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
      variables: { id: reportStandardId, file: upload, fileMarkings: [MARKING_TLP_GREEN] }
    }, addedDraftId);

    // Verify that validation bundle contains report
    const bundleData = await buildDraftValidationBundle(testContext, ADMIN_USER, addedDraftId);
    expect(bundleData.objects.length).toEqual(1);
    expect(bundleData.objects[0].id).toEqual(reportStandardId);
    expect(bundleData.objects[0].extensions[STIX_EXT_OCTI].files.length).toBe(1);
    expect(bundleData.objects[0].extensions[STIX_EXT_OCTI].files[0].data).toBeDefined();

    // Validate draft, verify work result and that draft was correctly deleted
    const validateResult = await adminQuery({
      query: VALIDATE_DRAFT_WORKSPACE_QUERY,
      variables: { id: addedDraftId },
    });
    expect(validateResult.data?.draftWorkspaceValidate).toBeDefined();
    expect(validateResult.data?.draftWorkspaceValidate.name).toEqual(`Draft validation ${addedDraftName} (${addedDraftId})`);
    expect(validateResult.data?.draftWorkspaceValidate.connector.id).toEqual(DRAFT_VALIDATION_CONNECTOR_ID);

    // Verify that draft still exists, but that the draft is in validated state.
    const draftWorkspaceResult = await adminQuery({
      query: READ_DRAFT_WORKSPACE_QUERY,
      variables: { id: addedDraftId }
    });

    expect(draftWorkspaceResult.data?.draftWorkspace).toBeDefined();
    expect(draftWorkspaceResult.data?.draftWorkspace.draft_status).toEqual(DRAFT_STATUS_VALIDATED);

    // Verify that me user has been moved outside of draft, and that me user can't move back into a draft in a validated state
    const meUserResult = await adminQuery({ query: READ_ME_USER_DRAFT_WORKSPACE_QUERY });
    expect(meUserResult.data?.me.draftContext).toBeNull();
    const meUserModifyResult = await adminQuery({
      query: MODIFY_USER_DRAFT_WORKSPACE_QUERY,
      variables: { input: { key: 'draft_context', value: addedDraftId } },
    });
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
    const report = await adminQuery({ query: CREATE_REPORT_QUERY, variables: REPORT_TO_CREATE });
    const reportStandardId = report.data.reportAdd.standard_id;
    await adminQuery({ query: REMOVE_STIX_CORE_OBJECT_FROM_DRAFT_QUERY, variables: { id: reportStandardId } });
    const getRemovedCreatedReportQuery = await adminQuery({ query: READ_REPORT_QUERY, variables: { id: reportStandardId } });
    expect(getRemovedCreatedReportQuery.data.report).toBeNull();

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
    const reportToUpdate = await adminQuery({ query: CREATE_REPORT_QUERY, variables: REPORT_TO_UPDATE });
    const reportToUpdateStandardId = reportToUpdate.data.reportAdd.standard_id;

    await modifyAdminDraftContext(addedDraftId);
    await adminQuery({
      query: UPDATE_REPORT_QUERY,
      variables: { id: reportToUpdateStandardId, input: { key: 'description', value: updateDescription } },
    });
    await adminQuery({ query: REMOVE_STIX_CORE_OBJECT_FROM_DRAFT_QUERY, variables: { id: reportToUpdateStandardId } });
    const reportAfterRemoval = await adminQuery({ query: READ_REPORT_QUERY, variables: { id: reportToUpdateStandardId } });
    expect(reportAfterRemoval.data.report.description).toBe(originalDescription);
    await modifyAdminDraftContext('');
    await adminQuery({
      query: DELETE_REPORT_QUERY,
      variables: { id: reportToUpdateStandardId },
    });

    // Verify that report deleted in draft is removed and reverted to live version
    const REPORT_TO_DELETE = {
      input: {
        name: 'Report to delete in draft',
        description: 'Report to delete in draft',
        published: '2020-02-26T00:51:35.000Z',
        confidence: 90,
      },
    };
    const reportToDelete = await adminQuery({ query: CREATE_REPORT_QUERY, variables: REPORT_TO_DELETE });
    const reportToDeleteStandardId = reportToDelete.data.reportAdd.standard_id;

    await modifyAdminDraftContext(addedDraftId);
    await adminQuery({
      query: DELETE_REPORT_QUERY,
      variables: { id: reportToDeleteStandardId },
    });
    const getReportDeletedQuery = await adminQuery({ query: READ_REPORT_QUERY, variables: { id: reportToDeleteStandardId } });
    expect(getReportDeletedQuery.data.report).toBeNull();
    await adminQuery({ query: REMOVE_STIX_CORE_OBJECT_FROM_DRAFT_QUERY, variables: { id: reportToDeleteStandardId } });
    const reportAfterDeleteRemoval = await adminQuery({ query: READ_REPORT_QUERY, variables: { id: reportToDeleteStandardId } });
    expect(reportAfterDeleteRemoval.data.report).toBeDefined();
    await modifyAdminDraftContext('');
    await adminQuery({
      query: DELETE_REPORT_QUERY,
      variables: { id: reportToDeleteStandardId },
    });
  });
});

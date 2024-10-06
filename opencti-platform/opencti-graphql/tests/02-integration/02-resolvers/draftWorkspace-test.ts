import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, adminQuery, queryAsAdmin, testContext } from '../../utils/testQuery';
import { MARKING_TLP_RED } from '../../../src/schema/identifier';
import { buildDraftValidationBundle } from '../../../src/modules/draftWorkspace/draftWorkspace-domain';
import { DRAFT_VALIDATION_CONNECTOR_ID } from '../../../src/modules/draftWorkspace/draftWorkspace-connector';

const CREATE_DRAFT_WORKSPACE_QUERY = gql`
    mutation DraftWorkspaceAdd($input: DraftWorkspaceAddInput!) {
        draftWorkspaceAdd(input: $input) {
            id
            standard_id
            name
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
                }
            }
        }
    }
`;

const MODIFY_USER_DRAFT_WORKSPACE_QUERY = gql`
    mutation MeUserWorkspaceModify($input: [EditInput]!) {
        meEdit(input: $input) {
            id
            draft_context
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

const modifyAdminDraftContext = async (draftId: string) => {
  const meUserModifyResult = await adminQuery({
    query: MODIFY_USER_DRAFT_WORKSPACE_QUERY,
    variables: { input: { key: 'draft_context', value: draftId } },
  });
  expect(meUserModifyResult.data?.meEdit.draft_context).toEqual(draftId);
};

describe('Drafts workspace resolver testing', () => {
  let addedDraftId = '';
  let addedDraftName = '';

  it('should create a draft', async () => {
    const draftName = 'testDraft';
    const createdDraft = await queryAsAdmin({
      query: CREATE_DRAFT_WORKSPACE_QUERY,
      variables: { input: { name: draftName } },
    });

    expect(createdDraft.data?.draftWorkspaceAdd).toBeDefined();
    expect(createdDraft.data?.draftWorkspaceAdd.name).toEqual(draftName);
    addedDraftId = createdDraft.data?.draftWorkspaceAdd.id;
    addedDraftName = createdDraft.data?.draftWorkspaceAdd.name;
  });

  it('should retrieve a draft by internal id', async () => {
    const draftWorkspaceResult = await queryAsAdmin({
      query: READ_DRAFT_WORKSPACE_QUERY,
      variables: { id: addedDraftId }
    });

    expect(draftWorkspaceResult.data?.draftWorkspace).toBeDefined();
    expect(draftWorkspaceResult.data?.draftWorkspace.name).toEqual(addedDraftName);
  });

  it('should list all drafts', async () => {
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

    // Verify that validation bundle contains report
    const bundleData = await buildDraftValidationBundle(testContext, ADMIN_USER, addedDraftId);
    expect(bundleData.objects.length).toEqual(1);
    expect(bundleData.objects[0].id).toEqual(reportStandardId);

    // Validate draft, verify work result and that draft was correctly deleted
    const validateResult = await queryAsAdmin({
      query: VALIDATE_DRAFT_WORKSPACE_QUERY,
      variables: { id: addedDraftId },
    });
    expect(validateResult.data?.draftWorkspaceValidate).toBeDefined();
    expect(validateResult.data?.draftWorkspaceValidate.name).toEqual(`Draft validation ${addedDraftName} (${addedDraftId})`);
    expect(validateResult.data?.draftWorkspaceValidate.connector.id).toEqual(DRAFT_VALIDATION_CONNECTOR_ID);
    const { data } = await queryAsAdmin({
      query: LIST_DRAFT_WORKSPACES_QUERY,
    });
    const drafts = data?.draftWorkspaces.edges;
    expect(drafts.length).toEqual(0);
  });
});

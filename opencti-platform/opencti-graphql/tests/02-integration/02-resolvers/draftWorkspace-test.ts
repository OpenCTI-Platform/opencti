import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

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

// const MODIFY_USER_DRAFT_WORKSPACE_QUERY = gql`
//     mutation MeUserWorkspaceModify($input: [EditInput]!) {
//         meEdit(input: $input) {
//             id
//             workspace_context
//         }
//     }
// `;
//
// const modifyUserWorkspace = async (draftId: string) => {
//   const meUserModifyResult = await queryAsAdmin({
//     query: MODIFY_USER_DRAFT_WORKSPACE_QUERY,
//     variables: { input: { key: 'workspace_context', value: draftId } },
//   });
//   expect(meUserModifyResult.data?.meEdit.workspace_context).toEqual(draftId);
// };

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

  it('create entity in draft context', async () => {
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
});

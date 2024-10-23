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

describe('Drafts workspace resolver testing', () => {
  it('should draft workspace be created', async () => {
    // Create draft workspace
    const DRAFT_WORKSPACE_TO_CREATE = {
      input: {
        name: 'TestDraftWorkspace',
      },
    };
    const draftWorkspace = await queryAsAdmin({ query: CREATE_DRAFT_WORKSPACE_QUERY, variables: DRAFT_WORKSPACE_TO_CREATE });

    const createdDraft = draftWorkspace.data?.draftWorkspaceAdd;
    await queryAsAdmin({ query: DELETE_DRAFT_WORKSPACE_QUERY, variables: { id: createdDraft.id } });

    expect(draftWorkspace.data?.draftWorkspaceAdd.id).toBeDefined();
  });
});

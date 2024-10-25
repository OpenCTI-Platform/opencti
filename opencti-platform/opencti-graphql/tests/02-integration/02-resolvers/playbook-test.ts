import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { adminQueryWithSuccess } from '../../utils/testQueryHelper';

const LIST_PLAYBOOKS = gql`
  query playbooks(
    $first: Int
    $after: ID
    $orderBy: PlaybooksOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    playbooks(
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

const CREATE_PLAYBOOK = gql`
  mutation playbookAdd($input: PlaybookAddInput!) {
    playbookAdd(input: $input){
      id
      name
    }
  }
`;

const READ_PLAYBOOK = gql`
  query playbook($id: String!) {
    playbook(id: $id) {
      id
      name
      description
      playbook_running
      playbook_definition
    }
  }
`;

const DELETE_PLAYBOOK = gql`
  mutation playbookDelete($id: ID!) {
    playbookDelete(id:$id)
  }
`;

describe('Playbook resolver standard behavior', () => {
  let playbookId = '';
  const playbookName = 'Playbook1';
  it('should list playbooks', async () => {
    const queryResult = await adminQueryWithSuccess({ query: LIST_PLAYBOOKS, variables: { first: 10 } });
    expect(queryResult.data?.playbooks.edges.length).toEqual(0);
  });
  it('should add playbook', async () => {
    const input = {
      input: {
        name: playbookName,
      }
    };
    const queryResult = await adminQueryWithSuccess({
      query: CREATE_PLAYBOOK,
      variables: input,
    });
    expect(queryResult.data?.playbookAdd.name).toEqual(playbookName);
    playbookId = queryResult.data?.playbookAdd.id;
  });
  it('should list playbooks', async () => {
    const queryResult = await adminQueryWithSuccess({ query: LIST_PLAYBOOKS, variables: { first: 10 } });
    expect(queryResult.data?.playbooks.edges.length).toEqual(1);
  });
  it('should read playbook', async () => {
    const queryResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
    expect(queryResult.data?.playbook.name).toEqual(playbookName);
    expect(queryResult.data?.playbook.playbook_running).toEqual(false);
  });
  it('should remove playbook', async () => {
    const queryResult = await adminQueryWithSuccess({
      query: DELETE_PLAYBOOK,
      variables: { id: playbookId },
    });
    expect(queryResult.data?.playbookDelete).toEqual(playbookId);
  });
});

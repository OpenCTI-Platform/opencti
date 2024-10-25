import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

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
  mutation playbookAdd($input: PlaybookAddInput!)
  {
    playbookAdd(input: $input){
      id
      name
    }
  }
`;
const DELETE_PLAYBOOK = gql`
  mutation playbookDelete($id: ID!){
    playbookDelete(id:$id)
  }`;

describe('Playbook resolver standard behavior', () => {
  let playbookId = '';
  it('should list playbooks', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_PLAYBOOKS, variables: { first: 10 } });
    expect(queryResult.data?.playbooks.edges.length).toEqual(0);
  });
  it('should add playbook', async () => {
    const input = {
      input: {
        name: 'Playbook1',
      }
    };
    const queryResult = await queryAsAdmin({
      query: CREATE_PLAYBOOK,
      variables: input,
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.playbookAdd.name).toEqual('Playbook1');
    playbookId = queryResult.data?.playbookAdd.id;
  });
  it('should remove playbook', async () => {
    const queryResult = await queryAsAdmin({
      query: DELETE_PLAYBOOK,
      variables: { id: playbookId },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.playbookDelete).toEqual(playbookId);
  });
});

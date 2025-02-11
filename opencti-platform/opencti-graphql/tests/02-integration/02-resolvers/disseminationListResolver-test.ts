import { describe, it, expect } from 'vitest';
import { disableEE, enableEE } from '../../utils/testQueryHelper';
import { queryAsAdmin } from '../../utils/testQuery';
import gql from 'graphql-tag';

const CREATE_QUERY = gql`
  mutation DisseminationListAdd($input: DisseminationListAddInput!) {
    disseminationListAdd(input: $input){
      id
      name
      description
      emails
    }
  }
`;

const READ_QUERY = gql`
  query disseminationList($id: ID!) {
    disseminationList(id: $id) {
      id
      standard_id
      name
      description
      emails
    }
  }
`;

const DELETE_QUERY = gql`
  mutation disseminationListDelete($id: ID!) {
    disseminationListDelete(id: $id)
  }
`;

describe('Dissemination list resolver', () => {
  let disseminationListInternalId: string;
  const DISSEMINATION_LIST_TO_CREATE = {
    input: {
      name: 'dissemination list 1',
      description: 'My dissemination list description',
      emails: ['email1@test.com', 'email2@test.com', 'email3@test.com'],
    }
  };

  it('should dissemination list created', async () => {
    await enableEE();
    const disseminationList = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: DISSEMINATION_LIST_TO_CREATE,
    });
    expect(disseminationList).not.toBeNull();
    expect(disseminationList.data?.disseminationListAdd).not.toBeNull();
    expect(disseminationList.data?.disseminationListAdd.name).toEqual(DISSEMINATION_LIST_TO_CREATE.input.name);
    expect(disseminationList.data?.disseminationListAdd.description).toEqual(DISSEMINATION_LIST_TO_CREATE.input.description);
    expect(disseminationList.data?.disseminationListAdd.emails).toEqual(DISSEMINATION_LIST_TO_CREATE.input.emails);
    disseminationListInternalId = disseminationList.data?.disseminationListAdd.id;
  });

  it('should dissemination list deleted', async () => {
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: disseminationListInternalId },
    });
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: disseminationListInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.disseminationList).toBeNull();
    await disableEE();
  });

});
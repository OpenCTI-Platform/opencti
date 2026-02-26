import gql from 'graphql-tag';
import { describe, expect, it } from 'vitest';
import { queryAsAdmin } from '../../utils/testQuery';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';

const READ_QUERY = gql`
  query StixCyberObservable($id: String!) {
    stixCyberObservable(id: $id) {
      id
    }
  }
`;

const CREATE_MUTATION = gql`
  mutation StixCyberObservableAdd($type: String!, $input: IMSIAddInput) {
    stixCyberObservableAdd(type: $type, IMSI: $input) {
      id
      observable_value
    }
  }
`;

const UPDATE_MUTATION = gql`
  mutation StixCyberObservableEdit($id: ID!, $input: [EditInput]!) {
    stixCyberObservableEdit(id: $id) {
      fieldPatch(input: $input) {
        id
        observable_value
      }
    }
  }
`;

const DELETE_MUTATION = gql`
  mutation stixCyberObservableDelete($id: ID!) {
    stixCyberObservableEdit(id: $id) {
      delete
    }
  }
`;

describe('SCO IMSI resolver standard behavior', () => {
  let internalId: string;

  it('should not create invalid IMSI', async () => {
    const response = await queryAsAdmin({
      query: CREATE_MUTATION,
      variables: {
        type: 'IMSI',
        input: { value: 'ABC123' },
      },
    });
    expect(response?.errors?.[0].message).toEqual('Observable is not correctly formatted');
  });

  it('should create IMSI', async () => {
    const response = await queryAsAdmin({
      query: CREATE_MUTATION,
      variables: {
        type: 'IMSI',
        input: { value: '313460000000001' },
      },
    });
    expect(response.data?.stixCyberObservableAdd).not.toBeNull();
    expect(response.data?.stixCyberObservableAdd.observable_value).toEqual('313460000000001');
    internalId = response.data?.stixCyberObservableAdd.id ?? '';
  });

  it('should not update invalid IMSI', async () => {
    const response = await queryAsAdmin({
      query: UPDATE_MUTATION,
      variables: {
        id: internalId,
        input: { key: 'value', value: 'ABC123' },
      },
    });
    expect(response.errors?.[0].message).toEqual('Observable of is not correctly formatted');
  });

  it('should update IMSI', async () => {
    const response = await queryAsAdminWithSuccess({
      query: UPDATE_MUTATION,
      variables: {
        id: internalId,
        input: { key: 'value', value: '313460000000002' },
      },
    });
    expect(response.data?.stixCyberObservableEdit.fieldPatch.observable_value).toEqual('313460000000002');
  });

  it('should delete IMSI', async () => {
    // Verify it exists
    let queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: internalId },
    });
    expect(queryResult.data?.stixCyberObservable).not.toBeNull();
    // Delete
    await queryAsAdminWithSuccess({
      query: DELETE_MUTATION,
      variables: { id: internalId },
    });
    // Verify is no longer found
    queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: internalId },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.stixCyberObservable).toBeNull();
  });
});

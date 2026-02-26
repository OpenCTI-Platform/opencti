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
  mutation StixCyberObservableAdd($type: String!, $input: ICCIDAddInput) {
    stixCyberObservableAdd(type: $type, ICCID: $input) {
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

describe('SCO ICCID resolver standard behavior', () => {
  let internalId: string;

  it('should not create invalid ICCID', async () => {
    const response = await queryAsAdmin({
      query: CREATE_MUTATION,
      variables: {
        type: 'ICCID',
        input: { value: 'ABC123' },
      },
    });
    expect(response?.errors?.[0].message).toEqual('Observable is not correctly formatted');
  });

  it('should create ICCID', async () => {
    const response = await queryAsAdmin({
      query: CREATE_MUTATION,
      variables: {
        type: 'ICCID',
        input: { value: '123456789012345678' },
      },
    });
    expect(response.data?.stixCyberObservableAdd).not.toBeNull();
    expect(response.data?.stixCyberObservableAdd.observable_value).toEqual('123456789012345678');
    internalId = response.data?.stixCyberObservableAdd.id ?? '';
  });

  it('should not update invalid ICCID', async () => {
    const response = await queryAsAdmin({
      query: UPDATE_MUTATION,
      variables: {
        id: internalId,
        input: { key: 'value', value: 'ABC123' },
      },
    });
    expect(response.errors?.[0].message).toEqual('Observable of is not correctly formatted');
  });

  it('should update ICCID', async () => {
    const response = await queryAsAdminWithSuccess({
      query: UPDATE_MUTATION,
      variables: {
        id: internalId,
        input: { key: 'value', value: '1234567890123456789' },
      },
    });
    expect(response.data?.stixCyberObservableEdit.fieldPatch.observable_value).toEqual('1234567890123456789');
  });

  it('should delete ICCID', async () => {
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

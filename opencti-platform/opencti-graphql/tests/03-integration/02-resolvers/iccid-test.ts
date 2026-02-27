import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { queryAsAdmin } from '../../utils/testQuery';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';

const READ_QUERY = gql`
  query StixCyberObservable($id: String!) {
    stixCyberObservable(id: $id) {
      id
    }
  }
`;

const CREATE_REL_QUERY = gql`
  mutation StixDomainRelationAdd($input: StixCoreRelationshipAddInput!) {
    stixCoreRelationshipAdd(input: $input) {
      id
      fromType
      toType
    }
  }
`;

const CREATE_MUTATION = gql`
  mutation StixCyberObservableAdd(
    $type: String!, 
    $iccid: ICCIDAddInput,
    $phoneNumber: PhoneNumberAddInput,
  ) {
    stixCyberObservableAdd(
      type: $type, 
      ICCID: $iccid,
      PhoneNumber: $phoneNumber,
    ) {
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
    const { errors } = await queryAsAdmin({
      query: CREATE_MUTATION,
      variables: {
        type: 'ICCID',
        iccid: { value: 'ABC123' },
      },
    });
    expect(errors?.[0].message).toEqual('Observable is not correctly formatted');
  });

  it('should create ICCID', async () => {
    const { data } = await queryAsAdmin({
      query: CREATE_MUTATION,
      variables: {
        type: 'ICCID',
        iccid: { value: '123456789012345678' },
      },
    });
    expect(data?.stixCyberObservableAdd).not.toBeNull();
    expect(data?.stixCyberObservableAdd.observable_value).toEqual('123456789012345678');
    internalId = data?.stixCyberObservableAdd.id ?? '';
  });

  it('should not update invalid ICCID', async () => {
    const { errors } = await queryAsAdmin({
      query: UPDATE_MUTATION,
      variables: {
        id: internalId,
        input: { key: 'value', value: 'ABC123' },
      },
    });
    expect(errors?.[0].message).toEqual('Observable of is not correctly formatted');
  });

  it('should update ICCID', async () => {
    const { data } = await queryAsAdminWithSuccess({
      query: UPDATE_MUTATION,
      variables: {
        id: internalId,
        input: { key: 'value', value: '1234567890123456789' },
      },
    });
    expect(data?.stixCyberObservableEdit.fieldPatch.observable_value).toEqual('1234567890123456789');
  });

  describe('Relationships section', () => {
    let phoneInternalId: string;

    beforeAll(async () => {
      const { data: dataPhoneNumber } = await queryAsAdmin({
        query: CREATE_MUTATION,
        variables: {
          type: 'Phone-Number',
          phoneNumber: { value: '0606060606' },
        },
      });
      phoneInternalId = dataPhoneNumber?.stixCyberObservableAdd.id ?? '';
    });

    afterAll(async () => {
      await queryAsAdmin({
        query: DELETE_MUTATION,
        variables: { id: phoneInternalId },
      });
    });

    it('should create a rel "resolves-to" between ICCID and Phone-Number', async () => {
      const { data } = await queryAsAdminWithSuccess({
        query: CREATE_REL_QUERY,
        variables: {
          input: {
            fromId: internalId,
            toId: phoneInternalId,
            relationship_type: 'resolves-to',
          },
        },
      });
      expect(data?.stixCoreRelationshipAdd).not.toBeNull();
      expect(data?.stixCoreRelationshipAdd.fromType).toEqual('ICCID');
      expect(data?.stixCoreRelationshipAdd.toType).toEqual('Phone-Number');
    });
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

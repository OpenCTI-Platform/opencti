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
    $imei: IMEIAddInput,
    $iccid: ICCIDAddInput,
    $macAddress: MacAddrAddInput,
  ) {
    stixCyberObservableAdd(
      type: $type,
      IMEI: $imei,
      ICCID: $iccid,
      MacAddr: $macAddress,
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

describe('SCO IMEI resolver standard behavior', () => {
  let internalId: string;

  it('should not create invalid IMEI', async () => {
    const { errors } = await queryAsAdmin({
      query: CREATE_MUTATION,
      variables: {
        type: 'IMEI',
        imei: { value: 'ABC123' },
      },
    });
    expect(errors?.[0].message).toEqual('Observable is not correctly formatted');
  });

  it('should create IMEI', async () => {
    const { data } = await queryAsAdmin({
      query: CREATE_MUTATION,
      variables: {
        type: 'IMEI',
        imei: { value: '112222223333334' },
      },
    });
    expect(data?.stixCyberObservableAdd).not.toBeNull();
    expect(data?.stixCyberObservableAdd.observable_value).toEqual('112222223333334');
    internalId = data?.stixCyberObservableAdd.id ?? '';
  });

  it('should not update invalid IMEI', async () => {
    const { errors } = await queryAsAdmin({
      query: UPDATE_MUTATION,
      variables: {
        id: internalId,
        input: { key: 'value', value: 'ABC123' },
      },
    });
    expect(errors?.[0].message).toEqual('Observable of is not correctly formatted');
  });

  it('should update IMEI', async () => {
    const { data } = await queryAsAdminWithSuccess({
      query: UPDATE_MUTATION,
      variables: {
        id: internalId,
        input: { key: 'value', value: '112222223333335' },
      },
    });
    expect(data?.stixCyberObservableEdit.fieldPatch.observable_value).toEqual('112222223333335');
  });

  describe('Relationships section', () => {
    let macAddressId: string;
    let iccidInternalId: string;

    beforeAll(async () => {
      const { data: dataIccid } = await queryAsAdmin({
        query: CREATE_MUTATION,
        variables: {
          type: 'ICCID',
          iccid: { value: '123456789012345999' },
        },
      });
      const { data: dataMacAddress } = await queryAsAdmin({
        query: CREATE_MUTATION,
        variables: {
          type: 'Mac-Addr',
          macAddress: { value: '00:1b:63:84:45:e6' },
        },
      });
      iccidInternalId = dataIccid?.stixCyberObservableAdd.id ?? '';
      macAddressId = dataMacAddress?.stixCyberObservableAdd.id ?? '';
    });

    afterAll(async () => {
      await queryAsAdmin({
        query: DELETE_MUTATION,
        variables: { id: iccidInternalId },
      });
      await queryAsAdmin({
        query: DELETE_MUTATION,
        variables: { id: macAddressId },
      });
    });

    it('should create a rel "uses" between IMEI and ICCID', async () => {
      const { data } = await queryAsAdminWithSuccess({
        query: CREATE_REL_QUERY,
        variables: {
          input: {
            fromId: internalId,
            toId: iccidInternalId,
            relationship_type: 'uses',
          },
        },
      });
      expect(data?.stixCoreRelationshipAdd).not.toBeNull();
      expect(data?.stixCoreRelationshipAdd.fromType).toEqual('IMEI');
      expect(data?.stixCoreRelationshipAdd.toType).toEqual('ICCID');
    });

    it('should create a rel "has" between IMEI and Mac-Addr', async () => {
      const { data } = await queryAsAdminWithSuccess({
        query: CREATE_REL_QUERY,
        variables: {
          input: {
            fromId: internalId,
            toId: macAddressId,
            relationship_type: 'has',
          },
        },
      });
      expect(data?.stixCoreRelationshipAdd).not.toBeNull();
      expect(data?.stixCoreRelationshipAdd.fromType).toEqual('IMEI');
      expect(data?.stixCoreRelationshipAdd.toType).toEqual('Mac-Addr');
    });
  });

  it('should delete IMEI', async () => {
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

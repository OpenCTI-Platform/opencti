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
    $imsi: IMSIAddInput,
    $imei: IMEIAddInput,
    $iccid: ICCIDAddInput,
    $phoneNumber: PhoneNumberAddInput,
  ) {
    stixCyberObservableAdd(
      type: $type, 
      IMSI: $imsi,
      IMEI: $imei,
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

describe('SCO IMSI resolver standard behavior', () => {
  let internalId: string;

  it('should not create invalid IMSI', async () => {
    const { errors } = await queryAsAdmin({
      query: CREATE_MUTATION,
      variables: {
        type: 'IMSI',
        imsi: { value: 'ABC123' },
      },
    });
    expect(errors?.[0].message).toEqual('Observable is not correctly formatted');
  });

  it('should create IMSI', async () => {
    const { data } = await queryAsAdminWithSuccess({
      query: CREATE_MUTATION,
      variables: {
        type: 'IMSI',
        imsi: { value: '313460000000001' },
      },
    });
    expect(data?.stixCyberObservableAdd).not.toBeNull();
    expect(data?.stixCyberObservableAdd.observable_value).toEqual('313460000000001');
    internalId = data?.stixCyberObservableAdd.id ?? '';
  });

  it('should not update invalid IMSI', async () => {
    const { errors } = await queryAsAdmin({
      query: UPDATE_MUTATION,
      variables: {
        id: internalId,
        input: { key: 'value', value: 'ABC123' },
      },
    });
    expect(errors?.[0].message).toEqual('Observable of is not correctly formatted');
  });

  it('should update IMSI', async () => {
    const { data } = await queryAsAdminWithSuccess({
      query: UPDATE_MUTATION,
      variables: {
        id: internalId,
        input: { key: 'value', value: '313460000000002' },
      },
    });
    expect(data?.stixCyberObservableEdit.fieldPatch.observable_value).toEqual('313460000000002');
  });

  describe('Relationships section', () => {
    let imeiInternalId: string;
    let iccidInternalId: string;
    let phoneInternalId: string;

    beforeAll(async () => {
      const { data: dataImei } = await queryAsAdmin({
        query: CREATE_MUTATION,
        variables: {
          type: 'IMEI',
          imei: { value: '123456789876543' },
        },
      });
      const { data: dataIccid } = await queryAsAdmin({
        query: CREATE_MUTATION,
        variables: {
          type: 'ICCID',
          iccid: { value: '123456789012345999' },
        },
      });
      const { data: dataPhoneNumber } = await queryAsAdmin({
        query: CREATE_MUTATION,
        variables: {
          type: 'Phone-Number',
          phoneNumber: { value: '0606060606' },
        },
      });
      imeiInternalId = dataImei?.stixCyberObservableAdd.id ?? '';
      iccidInternalId = dataIccid?.stixCyberObservableAdd.id ?? '';
      phoneInternalId = dataPhoneNumber?.stixCyberObservableAdd.id ?? '';
    });

    afterAll(async () => {
      await queryAsAdmin({
        query: DELETE_MUTATION,
        variables: { id: imeiInternalId },
      });
      await queryAsAdmin({
        query: DELETE_MUTATION,
        variables: { id: iccidInternalId },
      });
      await queryAsAdmin({
        query: DELETE_MUTATION,
        variables: { id: phoneInternalId },
      });
    });

    it('should create a rel "uses" between IMSI and IMEI', async () => {
      const { data } = await queryAsAdminWithSuccess({
        query: CREATE_REL_QUERY,
        variables: {
          input: {
            fromId: internalId,
            toId: imeiInternalId,
            relationship_type: 'uses',
          },
        },
      });
      expect(data?.stixCoreRelationshipAdd).not.toBeNull();
      expect(data?.stixCoreRelationshipAdd.fromType).toEqual('IMSI');
      expect(data?.stixCoreRelationshipAdd.toType).toEqual('IMEI');
    });

    it('should create a rel "has" between IMSI and ICCID', async () => {
      const { data } = await queryAsAdminWithSuccess({
        query: CREATE_REL_QUERY,
        variables: {
          input: {
            fromId: internalId,
            toId: iccidInternalId,
            relationship_type: 'has',
          },
        },
      });
      expect(data?.stixCoreRelationshipAdd).not.toBeNull();
      expect(data?.stixCoreRelationshipAdd.fromType).toEqual('IMSI');
      expect(data?.stixCoreRelationshipAdd.toType).toEqual('ICCID');
    });

    it('should create a rel "uses" between IMSI and Phone-Number', async () => {
      const { data } = await queryAsAdminWithSuccess({
        query: CREATE_REL_QUERY,
        variables: {
          input: {
            fromId: internalId,
            toId: phoneInternalId,
            relationship_type: 'uses',
          },
        },
      });
      expect(data?.stixCoreRelationshipAdd).not.toBeNull();
      expect(data?.stixCoreRelationshipAdd.fromType).toEqual('IMSI');
      expect(data?.stixCoreRelationshipAdd.toType).toEqual('Phone-Number');
    });
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

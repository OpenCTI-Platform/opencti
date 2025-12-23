import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { internalAdminQuery, queryAsAdmin } from '../../utils/testQuery';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';

const LIST_QUERY = `
  query stixCyberObservables(
    $first: Int
    $after: ID
    $orderBy: StixCyberObservablesOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    stixCyberObservables(
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
          observable_value
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query stixCyberObservable($id: String!) {
    stixCyberObservable(id: $id) {
      id
      observable_value
      toStix
    }
  }
`;

describe('StixCyberObservable resolver standard behavior', () => {
  let stixCyberObservableInternalId;
  let networkTrafficInternalId;
  const stixCyberObservableStixId = 'ipv4-addr--921c202b-5706-499d-9484-b5cf9bc6f70c';
  const sshKeyStixId = 'ssh-key--921c202b-5706-499d-9484-b5cf9bc6f70c';
  const iccidStixId = 'iccid--921c202b-5706-499d-9484-b5cf9bc6f70c';
  const imeiStixId = 'imei--921c202b-5706-499d-9484-b5cf9bc6f70c';
  const imsiStixId = 'imsi--921c202b-5706-499d-9484-b5cf9bc6f70c';
  let SSHInternalId;
  let ICCIDInternalId;
  let IMEIInternalId;
  let IMSIInternalId;

  const CREATE_QUERY = gql`
    mutation StixCyberObservableAdd(
      $type: String!,
      $IPv4Addr: IPv4AddrAddInput,
      $NetworkTraffic: NetworkTrafficAddInput,
      $SSHKey: SSHKeyAddInput,
      $Text: TextAddInput,
      $x_opencti_score: Int,
      $ICCID: ICCIDAddInput,
      $IMEI: IMEIAddInput,
      $IMSI: IMSIAddInput
    ) {
      stixCyberObservableAdd(type: $type,
        IPv4Addr: $IPv4Addr,
        NetworkTraffic: $NetworkTraffic,
        SSHKey: $SSHKey,
        Text: $Text,
        x_opencti_score: $x_opencti_score,
        ICCID: $ICCID,
        IMEI: $IMEI,
        IMSI: $IMSI
      ) {
        id
        observable_value
        x_opencti_score
        ... on IPv4Addr {
          value
        }
        ... on NetworkTraffic {
          dst_port
        }
        ... on Text {
          value
        }
        ... on SSHKey {
          key_type
          public_key
          fingerprint_sha256
        }
        ... on ICCID {
          value
        }
        ... on IMEI {
          value
        }
        ... on IMSI {
          value
        }
      }
    }
    `;

  const UPDATE_QUERY = gql`
    mutation StixCyberObservableEdit($id: ID!, $input: [EditInput]!) {
      stixCyberObservableEdit(id: $id) {
        fieldPatch(input: $input) {
          id
          x_opencti_score
          observable_value
        }
      }
    }
  `;

  it('should not create stixCyberObservable with score value outside of 0 and 100', async () => {
    // Create
    const STIX_OBSERVABLE_TO_CREATE = {
      type: 'Text',
      stix_id: 'text--921c202b-5706-499d-9484-b5cf9bc6f70c',
      Text: {
        value: 'Test',
      },
      x_opencti_score: 101,
    };
    const stixCyberObservable = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: STIX_OBSERVABLE_TO_CREATE,
    });
    expect(stixCyberObservable.errors[0].message).toEqual('The score should be an integer between 0 and 100');
  });
  it('should stixCyberObservable created', async () => {
    // Create the stixCyberObservable
    const STIX_OBSERVABLE_TO_CREATE = {
      type: 'IPv4-Addr',
      stix_id: stixCyberObservableStixId,
      IPv4Addr: {
        value: '8.8.8.8',
      },
    };
    const stixCyberObservable = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: STIX_OBSERVABLE_TO_CREATE,
    });
    expect(stixCyberObservable).not.toBeNull();
    expect(stixCyberObservable.data.stixCyberObservableAdd).not.toBeNull();
    expect(stixCyberObservable.data.stixCyberObservableAdd.observable_value).toEqual('8.8.8.8');
    stixCyberObservableInternalId = stixCyberObservable.data.stixCyberObservableAdd.id;
  });
  it('should stixCyberObservable network traffic created', async () => {
    // Create the stixCyberObservable
    const STIX_OBSERVABLE_TO_CREATE = {
      type: 'Network-Traffic',
      NetworkTraffic: {
        dst_port: 8090,
      },
    };
    const stixCyberObservable = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: STIX_OBSERVABLE_TO_CREATE,
    });
    expect(stixCyberObservable).not.toBeNull();
    expect(stixCyberObservable.data.stixCyberObservableAdd).not.toBeNull();
    expect(stixCyberObservable.data.stixCyberObservableAdd.observable_value).toEqual('8090');
    networkTrafficInternalId = stixCyberObservable.data.stixCyberObservableAdd.id;
  });
  it('should stixCyberObservable SSH_key created/update/delete', async () => {
    // Create the stixCyberObservable
    const STIX_OBSERVABLE_TO_CREATE = {
      type: 'SSH-Key',
      stix_id: sshKeyStixId,
      SSHKey: {
        key_type: 'rsa',
        public_key: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGmZ9d3b0QYpU2c9m7xKJ5V2rQy4s1aZr7Jk8Qw0t6u9',
        fingerprint_sha256: 'a35f9c12e84b07d46ab13e95c728f06d2a8e41bb9d630cfa7419e2568b30d96f'
      },
    };
    const stixCyberObservableSSH = await queryAsAdminWithSuccess({
      query: CREATE_QUERY,
      variables: STIX_OBSERVABLE_TO_CREATE,
    });
    expect(stixCyberObservableSSH.data.stixCyberObservableAdd).not.toBeNull();
    expect(stixCyberObservableSSH.data.stixCyberObservableAdd.public_key).toEqual('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGmZ9d3b0QYpU2c9m7xKJ5V2rQy4s1aZr7Jk8Qw0t6u9');
    expect(stixCyberObservableSSH.data.stixCyberObservableAdd.fingerprint_sha256).toEqual('a35f9c12e84b07d46ab13e95c728f06d2a8e41bb9d630cfa7419e2568b30d96f');
    expect(stixCyberObservableSSH.data.stixCyberObservableAdd.key_type).toEqual('rsa');
    SSHInternalId = stixCyberObservableSSH.data.stixCyberObservableAdd.id;

    // Update SSH Key
    const EDIT_QUERY = gql`
      mutation StixCyberObservableEdit($id: ID!, $input: [EditInput]!) {
        stixCyberObservableEdit(id: $id) {
          fieldPatch(input: $input) {
            ... on SSHKey {
                id
                key_type
                public_key
                fingerprint_sha256
            }
          }
        }
      }
    `;

    const stixCyberObservableUpdated = await queryAsAdminWithSuccess({
      query: EDIT_QUERY,
      variables: {
        id: SSHInternalId,
        input: [{ key: 'key_type', value: 'ecdsa' }, { key: 'public_key', value: '' }, { key: 'fingerprint_sha256', value: 'a35f9c12e84b07d46ab13e95c728f06d2a8e41bb9d630cfa7419e2568b30d97f' }]
      },
    });
    expect(stixCyberObservableUpdated.data.stixCyberObservableEdit.fieldPatch.key_type).toEqual('ecdsa');
    expect(stixCyberObservableUpdated.data.stixCyberObservableEdit.fieldPatch.public_key).toEqual('');
    expect(stixCyberObservableUpdated.data.stixCyberObservableEdit.fieldPatch.fingerprint_sha256).toEqual('a35f9c12e84b07d46ab13e95c728f06d2a8e41bb9d630cfa7419e2568b30d97f');

    // Delete SSH Key
    const DELETE_QUERY = gql`
      mutation stixCyberObservableDelete($id: ID!) {
        stixCyberObservableEdit(id: $id) {
          delete
        }
      }
    `;

    await queryAsAdminWithSuccess({
      query: DELETE_QUERY,
      variables: { id: SSHInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: sshKeyStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixCyberObservable).toBeNull();
  });
  it('should stixCyberObservable loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixCyberObservableInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixCyberObservable).not.toBeNull();
    expect(queryResult.data.stixCyberObservable.id).toEqual(stixCyberObservableInternalId);
    expect(queryResult.data.stixCyberObservable.toStix.length).toBeGreaterThan(5);
  });
  it('should list stixCyberObservables', async () => {
    const queryResult = await queryAsAdmin({ query: gql(LIST_QUERY), variables: { first: 10 } });
    expect(queryResult.data.stixCyberObservables.edges.length).toEqual(6);
  });
  it('should list stixCyberObservables orderBy observable_value', async () => {
    const queryResult = await internalAdminQuery(LIST_QUERY, { first: 10, orderBy: 'observable_value', orderMode: 'desc' });
    expect(queryResult.data.stixCyberObservables).not.toBeNull();
    expect(queryResult.data.stixCyberObservables.edges.length).toEqual(6);
  });
  it('should update stixCyberObservable', async () => {
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: {
        id: stixCyberObservableInternalId,
        input: { key: 'x_opencti_score', value: '20' },
      },
    });
    expect(queryResult.data.stixCyberObservableEdit.fieldPatch.x_opencti_score).toEqual(20);
  });
  it('should not update stixCyberObservable with score value outside of 0 and 100', async () => {
    // Update above 100
    const queryResultAbove100 = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: {
        id: stixCyberObservableInternalId,
        input: { key: 'x_opencti_score', value: '142' },
      },
    });
    expect(queryResultAbove100.errors[0].message).toEqual('The score should be an integer between 0 and 100');
    // Update below 0
    const queryResultBelow0 = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: {
        id: stixCyberObservableInternalId,
        input: { key: 'x_opencti_score', value: '-42' },
      },
    });
    expect(queryResultBelow0.errors[0].message).toEqual('The score should be an integer between 0 and 100');
  });
  it('should update mutliple attributes', async () => {
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: {
        id: stixCyberObservableInternalId,
        input: [{ key: 'x_opencti_score', value: '60' }, { key: 'value', value: '8.8.8.9' }],
      },
    });
    expect(queryResult.data.stixCyberObservableEdit.fieldPatch.x_opencti_score).toEqual(60);
    expect(queryResult.data.stixCyberObservableEdit.fieldPatch.observable_value).toEqual('8.8.8.9');
  });
  it('should not update mutliple attributes if incorrect score value', async () => {
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: {
        id: stixCyberObservableInternalId,
        input: [{ key: 'observable_value', value: '8.8.8.9' }, { key: 'x_opencti_score', value: '160' }],
      },
    });
    expect(queryResult.errors[0].message).toEqual('The score should be an integer between 0 and 100');
  });
  it('should context patch stixCyberObservable', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation StixCyberObservableEdit($id: ID!, $input: EditContext) {
        stixCyberObservableEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: stixCyberObservableInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.stixCyberObservableEdit.contextPatch.id).toEqual(stixCyberObservableInternalId);
  });
  it('should context clean stixCyberObservable', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation StixCyberObservableEdit($id: ID!) {
        stixCyberObservableEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
      `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: stixCyberObservableInternalId },
    });
    expect(queryResult.data.stixCyberObservableEdit.contextClean.id).toEqual(stixCyberObservableInternalId);
  });
  it('should add relation in stixCyberObservable', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation StixCyberObservableEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
        stixCyberObservableEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on StixCyberObservable {
                objectMarking {
                  id
                }
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_ADD_QUERY,
      variables: {
        id: stixCyberObservableInternalId,
        input: {
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.stixCyberObservableEdit.relationAdd.from.objectMarking.length).toEqual(1);
  });
  it('should delete relation in stixCyberObservable', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation StixCyberObservableEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        stixCyberObservableEdit(id: $id) {
          relationDelete(toId: $toId, relationship_type: $relationship_type) {
            id
            objectMarking {
              id
            }
          }
        }
      }
  `;
    const queryResult = await queryAsAdmin({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: stixCyberObservableInternalId,
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.stixCyberObservableEdit.relationDelete.objectMarking.length).toEqual(0);
  });
  it('should add observable in note', async () => {
    const CREATE_NOTE_QUERY = gql`
      mutation NoteAdd($input: NoteAddInput!) {
        noteAdd(input: $input) {
          id
          attribute_abstract
          content
        }
      }
  `;
    // Create the note
    const NOTE_TO_CREATE = {
      input: {
        attribute_abstract: 'Note description',
        content: 'Test content',
        objects: [stixCyberObservableInternalId],
        createdBy: 'identity--7b82b010-b1c0-4dae-981f-7756374a17df',
      },
    };
    const note = await queryAsAdmin({
      query: CREATE_NOTE_QUERY,
      variables: NOTE_TO_CREATE,
    });
    expect(note).not.toBeNull();
    expect(note.data.noteAdd).not.toBeNull();
    expect(note.data.noteAdd.attribute_abstract).toEqual('Note description');
    const noteInternalId = note.data.noteAdd.id;
    const DELETE_QUERY = gql`
      mutation noteDelete($id: ID!) {
        noteEdit(id: $id) {
          delete
        }
      }
      `;
    // Delete the note
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: noteInternalId },
    });
    const READ_NOTE_QUERY = gql`
      query note($id: String!) {
        note(id: $id) {
          id
          standard_id
          attribute_abstract
          content
        }
      }
    `;
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_NOTE_QUERY, variables: { id: noteInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.note).toBeNull();
  });
  it('should stixCyberObservable deleted', async () => {
    const DELETE_QUERY = gql`
      mutation stixCyberObservableDelete($id: ID!) {
        stixCyberObservableEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the stixCyberObservable
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: stixCyberObservableInternalId },
    });
    // delete network traffic
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: networkTrafficInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixCyberObservableStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixCyberObservable).toBeNull();
  });
  it('should not create invalid ICCID stixCyberObservable', async () => {
    // Create the ICCID stixCyberObservable
    const STIX_OBSERVABLE_TO_CREATE = {
      type: 'ICCID',
      stix_id: iccidStixId,
      ICCID: {
        value: 'ABC123'
      }
    };
    const stixCyberObservableICCID = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: STIX_OBSERVABLE_TO_CREATE,
    });
    console.log(stixCyberObservableICCID);
    expect(stixCyberObservableICCID.errors[0].message).toEqual('Observable is not correctly formatted');
  });
  it('should stixCyberObservable ICCID create', async () => {
    // Create the ICCID stixCyberObservable
    const STIX_OBSERVABLE_TO_CREATE = {
      type: 'ICCID',
      stix_id: iccidStixId,
      ICCID: {
        value: '123456789012345678',
      },
    };
    const stixCyberObservableICCID = await await queryAsAdmin({
      query: CREATE_QUERY,
      variables: STIX_OBSERVABLE_TO_CREATE,
    });
    expect(stixCyberObservableICCID).not.toBeNull();
    expect(stixCyberObservableICCID.data.stixCyberObservableAdd).not.toBeNull();
    expect(stixCyberObservableICCID.data.stixCyberObservableAdd.observable_value).toEqual('123456789012345678');
    ICCIDInternalId = stixCyberObservableICCID.data.stixCyberObservableAdd.id;
  });
  it('should not update invalid ICCID stixCyberObservable', async () => {
    // Update ICCID
    const stixCyberObservableUpdated = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: {
        id: ICCIDInternalId,
        input: { key: 'value', value: 'ABC123' },
      },
    });
    expect(stixCyberObservableUpdated.errors[0].message).toEqual('Observable of is not correctly formatted');
  });
  it('should stixCyberObservable ICCID update', async () => {
    // Update ICCID
    const stixCyberObservableUpdated = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: {
        id: ICCIDInternalId,
        input: { key: 'value', value: '1234567890123456789' },
      },
    });
    expect(stixCyberObservableUpdated.data.stixCyberObservableEdit.fieldPatch.observable_value).toEqual('1234567890123456789');
  });
  it('should stixCyberObservable ICCID delete', async () => {
    // Delete ICCID
    const DELETE_QUERY = gql`
      mutation stixCyberObservableDelete($id: ID!) {
        stixCyberObservableEdit(id: $id) {
          delete
        }
      }
    `;
    await queryAsAdminWithSuccess({
      query: DELETE_QUERY,
      variables: { id: ICCIDInternalId},
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: iccidStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixCyberObservable).toBeNull();
  });
  it('should not create invalid IMEI stixCyberObservable', async () => {
    // Create the IMEI stixCyberObservable
    const STIX_OBSERVABLE_TO_CREATE = {
      type: 'IMEI',
      stix_id: imeiStixId,
      IMEI: {
        value: 'ABC123'
      }
    };
    const stixCyberObservableIMEI = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: STIX_OBSERVABLE_TO_CREATE,
    });
    console.log(stixCyberObservableIMEI);
    expect(stixCyberObservableIMEI.errors[0].message).toEqual('Observable is not correctly formatted');
  });
  it('should stixCyberObservable IMEI created', async () => {
    // Create the IMEI stixCyberObservable
    const STIX_OBSERVABLE_TO_CREATE = {
      type: 'IMEI',
      stix_id: imeiStixId,
      IMEI: {
        value: '112222223333334'
      }
    };
    const stixCyberObservableIMEI = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: STIX_OBSERVABLE_TO_CREATE,
    });
    expect(stixCyberObservableIMEI).not.toBeNull();
    expect(stixCyberObservableIMEI.data.stixCyberObservableAdd).not.toBeNull();
    expect(stixCyberObservableIMEI.data.stixCyberObservableAdd.observable_value).toEqual('112222223333334');
    IMEIInternalId = stixCyberObservableIMEI.data.stixCyberObservableAdd.id;
  });
  it('should not update invalid IMEI stixCyberObservable', async () => {
    // Update IMEI
    const stixCyberObservableUpdated = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: {
        id: IMEIInternalId,
        input: { key: 'value', value: 'ABC123' }
      },
    });
    expect(stixCyberObservableUpdated.errors[0].message).toEqual('Observable of is not correctly formatted');
  });
  it('should stixCyberObservable IMEI update', async () => {
    // Update IMEI
    const stixCyberObservableUpdated = await queryAsAdminWithSuccess({
      query: UPDATE_QUERY,
      variables: {
        id: IMEIInternalId,
        input: { key: 'value', value: '112222223333335' }
      },
    });
    expect(stixCyberObservableUpdated.data.stixCyberObservableEdit.fieldPatch.observable_value).toEqual('112222223333335');
  });
  it('should stixCyberObservable IMEI delete', async () => {
    // Delete IMEI
    const DELETE_QUERY = gql`
      mutation stixCyberObservableDelete($id: ID!) {
        stixCyberObservableEdit(id: $id) {
          delete
        }
      }
    `;

    await queryAsAdminWithSuccess({
      query: DELETE_QUERY,
      variables: { id: IMEIInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: imeiStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixCyberObservable).toBeNull();
  });
  it('should not create invalid IMSI stixCyberObservable', async () => {
    // Create the IMSI stixCyberObservable
    const STIX_OBSERVABLE_TO_CREATE = {
      type: 'IMSI',
      stix_id: imsiStixId,
      IMSI: {
        value: 'ABC123'
      }
    };
    const stixCyberObservableIMSI = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: STIX_OBSERVABLE_TO_CREATE,
    });
    console.log(stixCyberObservableIMSI);
    expect(stixCyberObservableIMSI.errors[0].message).toEqual('Observable is not correctly formatted');
  });
  it('should stixCyberObservable IMSI created', async () => {
    // Create the IMSI stixCyberObservable
    const STIX_OBSERVABLE_TO_CREATE = {
      type: 'IMSI',
      stix_id: imsiStixId,
      IMSI: {
        value: '313460000000001'
      }
    };
    const stixCyberObservableIMSI = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: STIX_OBSERVABLE_TO_CREATE,
    });
    expect(stixCyberObservableIMSI).not.toBeNull();
    expect(stixCyberObservableIMSI.data.stixCyberObservableAdd).not.toBeNull();
    expect(stixCyberObservableIMSI.data.stixCyberObservableAdd.observable_value).toEqual('313460000000001');
    IMSIInternalId = stixCyberObservableIMSI.data.stixCyberObservableAdd.id;
  });
  it('should not update invalid IMSI stixCyberObservable', async () => {
    // Update IMSI
    const stixCyberObservableUpdated = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: {
        id: IMSIInternalId,
        input: { key: 'value', value: 'ABC123' }
      },
    });
    expect(stixCyberObservableUpdated.errors[0].message).toEqual('Observable of is not correctly formatted');
  });
  it('should stixCyberObservable IMSI update', async () => {
    // Update IMSI
    const stixCyberObservableUpdated = await queryAsAdminWithSuccess({
      query: UPDATE_QUERY,
      variables: {
        id: IMSIInternalId,
        input: { key: 'value', value: '313460000000002' }
      },
    });
    expect(stixCyberObservableUpdated.data.stixCyberObservableEdit.fieldPatch.observable_value).toEqual('313460000000002');
  });
  it('should stixCyberObservable IMSI delete', async () => {
    // Delete IMSI
    const DELETE_QUERY = gql`
      mutation stixCyberObservableDelete($id: ID!) {
        stixCyberObservableEdit(id: $id) {
          delete
        }
      }
    `;

    await queryAsAdminWithSuccess({
      query: DELETE_QUERY,
      variables: { id: IMSIInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: imsiStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixCyberObservable).toBeNull();
  });
});

describe('StixCyberObservable resolver promote to indicator behavior', () => {
  let stixCyberObservableInternalId;
  let indicatorInternalId;
  it('should stixCyberObservable created', async () => { // 1 create
    const CREATE_QUERY = gql`
      mutation StixCyberObservableCreationMutation(
        $type: String!
        $x_opencti_score: Int
        $x_opencti_description: String
        $Artifact: ArtifactAddInput
      ) {
        stixCyberObservableAdd(
          type: $type, 
          x_opencti_score: $x_opencti_score, 
          x_opencti_description: $x_opencti_description, 
          Artifact: $Artifact
        ) {
          id
          standard_id
          observable_value
          ... on Software {
            name
          }
        }
      }
    `;
    // Create the stixCyberObservable
    const STIX_OBSERVABLE_TO_CREATE = {
      type: 'Artifact',
      x_opencti_score: 50,
      x_opencti_description: 'Artifact uploaded',
      Artifact: {
        decryption_key: '',
        encryption_algorithm: '',
        mime_type: 'application/xml',
        payload_bin: '',
        url: '',
        x_opencti_additional_names: [
          '[Content_Types].xml'
        ],
        hashes: [
          {
            algorithm: 'MD5',
            hash: '46c293d9de7b32344e041857515944a6'
          },
          {
            algorithm: 'SHA-1',
            hash: 'dfe5e1bcc496efac6012e26f013c7b6a6d7c9803'
          },
          {
            algorithm: 'SHA-256',
            hash: 'bfa02ea1994b73dca866ea3b6596340fe00063d19eab5957c7d8e6a5fa10599a'
          },
          {
            algorithm: 'SHA-512',
            hash: '0ecf269f1805d6ccc61b247ba7aadd66771b86554509536bb90988b6b0f09521e84167496fd6b9bb3153ae25af6d461c43faae23c75ca4fa050b41d5133a54ba'
          }
        ]
      },
    };
    const stixCyberObservable = await queryAsAdminWithSuccess({
      query: CREATE_QUERY,
      variables: STIX_OBSERVABLE_TO_CREATE,
    });
    expect(stixCyberObservable.data.stixCyberObservableAdd).not.toBeNull();
    expect(stixCyberObservable.data.stixCyberObservableAdd.observable_value).toEqual('0ecf269f1805d6ccc61b247ba7aadd66771b86554509536bb90988b6b0f09521e84167496fd6b9bb3153ae25af6d461c43faae23c75ca4fa050b41d5133a54ba');
    stixCyberObservableInternalId = stixCyberObservable.data.stixCyberObservableAdd.id;
  });
  it('should promote observable to indicator', async () => { // + 1 create
    const PROMOTE_QUERY = gql`
      mutation StixCyberObservableIndicatorsPromoteMutation(
        $id: ID!
      ) {
        stixCyberObservableEdit(id: $id) {
          promoteToIndicator {
            id
            name
            pattern
          }
        }
      }
    `;
    // Create the indicator
    const indicator = await queryAsAdminWithSuccess({
      query: PROMOTE_QUERY,
      variables: { id: stixCyberObservableInternalId },
    });
    const expectedPattern = "[file:hashes.'SHA-256' = 'bfa02ea1994b73dca866ea3b6596340fe00063d19eab5957c7d8e6a5fa10599a' OR file:hashes.'SHA-512' = '0ecf269f1805d6ccc61b247ba7aadd66771b86554509536bb90988b6b0f09521e84167496fd6b9bb3153ae25af6d461c43faae23c75ca4fa050b41d5133a54ba' OR file:hashes.'SHA-1' = 'dfe5e1bcc496efac6012e26f013c7b6a6d7c9803' OR file:hashes.MD5 = '46c293d9de7b32344e041857515944a6']";
    expect(indicator.data.stixCyberObservableEdit.promoteToIndicator.name).toEqual('0ecf269f1805d6ccc61b247ba7aadd66771b86554509536bb90988b6b0f09521e84167496fd6b9bb3153ae25af6d461c43faae23c75ca4fa050b41d5133a54ba');
    expect(indicator.data.stixCyberObservableEdit.promoteToIndicator.pattern).toEqual(expectedPattern);
    indicatorInternalId = indicator.data.stixCyberObservableEdit.promoteToIndicator.id;
  });
  it('should indicators be deleted', async () => { // +1 delete
    const DELETE_QUERY = gql`
      mutation indicatorDelete($id: ID!) {
        indicatorDelete(id: $id)
      }
    `;
    // Delete the indicator
    const deleteIndicator = await queryAsAdminWithSuccess({
      query: DELETE_QUERY,
      variables: { id: indicatorInternalId },
    });

    expect(deleteIndicator.data?.indicatorDelete).toEqual(indicatorInternalId);
  });
  it('should stixCyberObservable deleted', async () => { // +1 delete
    const DELETE_QUERY = gql`
      mutation stixCyberObservableDelete($id: ID!) {
        stixCyberObservableEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the stixCyberObservable
    await queryAsAdminWithSuccess({
      query: DELETE_QUERY,
      variables: { id: stixCyberObservableInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdminWithSuccess({ query: READ_QUERY, variables: { id: stixCyberObservableInternalId } });
    expect(queryResult.data.stixCyberObservable).toBeNull();
  });
});

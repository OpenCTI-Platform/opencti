import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdminWithSuccess, queryAsAdmin } from '../../utils/testQueryHelper';
import { isRuntimeSortEnable } from '../../../src/database/engine';

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
  let SSHInternalId;

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

  it('should stixCyberObservable created with mixed-case hashes preserve case in promoted pattern', async () => {
    const CREATE_QUERY_MIXED = gql`
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
        }
      }
    `;
    // Mixed-case hashes (some upper-case hex)
    const STIX_OBSERVABLE_TO_CREATE_MIXED = {
      type: 'Artifact',
      x_opencti_score: 50,
      x_opencti_description: 'Artifact uploaded mixed case',
      Artifact: {
        decryption_key: '',
        encryption_algorithm: '',
        mime_type: 'application/xml',
        payload_bin: '',
        url: '',
        x_opencti_additional_names: [
          '[Content_Types].xml',
        ],
        hashes: [
          {
            algorithm: 'MD5',
            hash: '46C293D9DE7B32344E041857515944A6',
          },
          {
            algorithm: 'SHA-1',
            hash: 'DFE5E1BCC496EFAC6012E26F013C7B6A6D7C9803',
          },
          {
            algorithm: 'SHA-256',
            hash: 'BFA02EA1994B73DCA866EA3B6596340FE00063D19EAB5957C7D8E6A5FA10599A',
          },
          {
            algorithm: 'SHA-512',
            hash: '0ECF269F1805D6CCC61B247BA7AADD66771B86554509536BB90988B6B0F09521E84167496FD6B9BB3153AE25AF6D461C43FAAE23C75CA4FA050B41D5133A54BA',
          },
        ],
      },
    };
    const created = await queryAsAdminWithSuccess({
      query: CREATE_QUERY_MIXED,
      variables: STIX_OBSERVABLE_TO_CREATE_MIXED,
    });
    expect(created.data.stixCyberObservableAdd).not.toBeNull();
    const internalId = created.data.stixCyberObservableAdd.id;

    // Promote to indicator and expect pattern to contain the same mixed-case hashes
    const PROMOTE_QUERY = gql`
      mutation StixCyberObservableIndicatorsPromoteMutation($id: ID!) {
        stixCyberObservableEdit(id: $id) {
          promoteToIndicator {
            id
            name
            pattern
          }
        }
      }
    `;
    const promoted = await queryAsAdminWithSuccess({ query: PROMOTE_QUERY, variables: { id: internalId } });
    expect(promoted.data.stixCyberObservableEdit.promoteToIndicator).not.toBeNull();
    const expectedPatternMixed = "[file:hashes.'SHA-256' = 'BFA02EA1994B73DCA866EA3B6596340FE00063D19EAB5957C7D8E6A5FA10599A' OR file:hashes.'SHA-512' = '0ECF269F1805D6CCC61B247BA7AADD66771B86554509536BB90988B6B0F09521E84167496FD6B9BB3153AE25AF6D461C43FAAE23C75CA4FA050B41D5133A54BA' OR file:hashes.'SHA-1' = 'DFE5E1BCC496EFAC6012E26F013C7B6A6D7C9803' OR file:hashes.MD5 = '46C293D9DE7B32344E041857515944A6']";
    expect(promoted.data.stixCyberObservableEdit.promoteToIndicator.pattern).toEqual(expectedPatternMixed);

    // Cleanup: delete the indicator and the observable
    const indicatorId = promoted.data.stixCyberObservableEdit.promoteToIndicator.id;
    const DELETE_INDICATOR = gql`
      mutation indicatorDelete($id: ID!) {
        indicatorDelete(id: $id)
      }
    `;
    await queryAsAdminWithSuccess({ query: DELETE_INDICATOR, variables: { id: indicatorId } });
    const DELETE_STIX = gql`
      mutation stixCyberObservableDelete($id: ID!) {
        stixCyberObservableEdit(id: $id) { delete }
      }
    `;
    await queryAsAdminWithSuccess({ query: DELETE_STIX, variables: { id: internalId } });
  });
  it('should stixCyberObservable creation return the indicator created with it', async () => {
    const CREATE_WITH_INDICATOR_QUERY = gql`
      mutation StixCyberObservableAddWithIndicator($createIndicator: Boolean, $DomainName: DomainNameAddInput) {
        stixCyberObservableAdd(type: "Domain-Name", createIndicator: $createIndicator, DomainName: $DomainName) {
          id
          createdIndicator {
            id
            entity_type
            pattern
          }
        }
      }
    `;
    const variables = { createIndicator: true, DomainName: { value: 'created-indicator-test.com' } };
    const created = await queryAsAdminWithSuccess({ query: CREATE_WITH_INDICATOR_QUERY, variables });
    const { id: observableId, createdIndicator } = created.data.stixCyberObservableAdd;
    expect(createdIndicator).not.toBeNull();
    expect(createdIndicator.entity_type).toEqual('Indicator');
    expect(createdIndicator.pattern).toEqual("[domain-name:value = 'created-indicator-test.com']");

    // Created again (upsert): the same indicator is returned
    const upserted = await queryAsAdminWithSuccess({ query: CREATE_WITH_INDICATOR_QUERY, variables });
    expect(upserted.data.stixCyberObservableAdd.id).toEqual(observableId);
    expect(upserted.data.stixCyberObservableAdd.createdIndicator.id).toEqual(createdIndicator.id);

    // Without createIndicator, no indicator is given
    const withoutIndicator = await queryAsAdminWithSuccess({
      query: CREATE_WITH_INDICATOR_QUERY,
      variables: { ...variables, createIndicator: false },
    });
    expect(withoutIndicator.data.stixCyberObservableAdd.createdIndicator).toBeNull();

    // Cleanup: delete the indicator and the observable
    await queryAsAdminWithSuccess({
      query: gql`mutation indicatorDelete($id: ID!) { indicatorDelete(id: $id) }`,
      variables: { id: createdIndicator.id },
    });
    await queryAsAdminWithSuccess({
      query: gql`mutation stixCyberObservableDelete($id: ID!) { stixCyberObservableEdit(id: $id) { delete } }`,
      variables: { id: observableId },
    });
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
        fingerprint_sha256: 'a35f9c12e84b07d46ab13e95c728f06d2a8e41bb9d630cfa7419e2568b30d96f',
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
        input: [{ key: 'key_type', value: 'ecdsa' }, { key: 'public_key', value: '' }, { key: 'fingerprint_sha256', value: 'a35f9c12e84b07d46ab13e95c728f06d2a8e41bb9d630cfa7419e2568b30d97f' }],
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
  it('should list stixCyberObservables orderBy observable_value, or refuse it without runtime sorting', async () => {
    const queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: { first: 10, orderBy: 'observable_value', orderMode: 'desc' },
    });
    if (isRuntimeSortEnable()) {
      // Elasticsearch: the sort works
      expect(queryResult.data.stixCyberObservables).not.toBeNull();
      expect(queryResult.data.stixCyberObservables.edges.length).toEqual(6);
    } else {
      // OpenSearch: the API refuses this sort with an explicit error
      expect(queryResult.errors?.[0].message).toBe('Runtime mapping is only possible with elastic >=7.12');
    }
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
          '[Content_Types].xml',
        ],
        hashes: [
          {
            algorithm: 'MD5',
            hash: '46c293d9de7b32344e041857515944a6',
          },
          {
            algorithm: 'SHA-1',
            hash: 'dfe5e1bcc496efac6012e26f013c7b6a6d7c9803',
          },
          {
            algorithm: 'SHA-256',
            hash: 'bfa02ea1994b73dca866ea3b6596340fe00063d19eab5957c7d8e6a5fa10599a',
          },
          {
            algorithm: 'SHA-512',
            hash: '0ecf269f1805d6ccc61b247ba7aadd66771b86554509536bb90988b6b0f09521e84167496fd6b9bb3153ae25af6d461c43faae23c75ca4fa050b41d5133a54ba',
          },
        ],
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

describe('Network Traffic deduplication on import', () => {
  // Same shape as the pycti import of a STIX bundle: refs are given by their bundle ids
  const ipv4BundleId = 'ipv4-addr--041e5d33-1ef7-455f-a5e7-4ed863a9c95d';
  const networkTrafficBundleId = 'network-traffic--0d1dcaf5-ccde-4aff-b9e5-f1e70698042f';
  const otherNetworkTrafficBundleId = 'network-traffic--d2c21f07-e9d9-4fdd-af8e-9bb1b9501c81';
  // STIX 2.1 deterministic ids, computed outside the platform
  const ipv4StandardId = 'ipv4-addr--efb3cb24-5b02-57b0-adb6-64563650dafa';
  const networkTrafficStandardId = 'network-traffic--2cc6d858-8854-576e-bad1-46d121fa8497';
  let ipv4InternalId;
  let networkTrafficInternalId;

  const ADD_QUERY = gql`
    mutation NetworkTrafficDeduplicationAdd(
      $type: String!,
      $stix_id: StixId,
      $update: Boolean,
      $x_opencti_score: Int,
      $IPv4Addr: IPv4AddrAddInput,
      $NetworkTraffic: NetworkTrafficAddInput
    ) {
      stixCyberObservableAdd(type: $type, stix_id: $stix_id, update: $update, x_opencti_score: $x_opencti_score, IPv4Addr: $IPv4Addr, NetworkTraffic: $NetworkTraffic) {
        id
        standard_id
        x_opencti_stix_ids
        x_opencti_score
      }
    }
  `;

  const EDIT_QUERY = gql`
    mutation NetworkTrafficDeduplicationEdit($id: ID!, $input: [EditInput]!) {
      stixCyberObservableEdit(id: $id) {
        fieldPatch(input: $input) {
          id
          standard_id
          x_opencti_stix_ids
        }
      }
    }
  `;

  const DELETE_QUERY = gql`
    mutation NetworkTrafficDeduplicationDelete($id: ID!) {
      stixCyberObservableEdit(id: $id) {
        delete
      }
    }
  `;

  const importNetworkTraffic = async (stixId, score) => {
    const result = await queryAsAdminWithSuccess({
      query: ADD_QUERY,
      variables: { type: 'Network-Traffic', stix_id: stixId, update: true, x_opencti_score: score, NetworkTraffic: { networkDst: ipv4BundleId, protocols: ['tcp'] } },
    });
    return result.data.stixCyberObservableAdd;
  };

  it('should create the referenced IPv4 with its bundle id', async () => {
    const result = await queryAsAdminWithSuccess({
      query: ADD_QUERY,
      variables: { type: 'IPv4-Addr', stix_id: ipv4BundleId, IPv4Addr: { value: '198.51.100.77' } },
    });
    const ipv4 = result.data.stixCyberObservableAdd;
    expect(ipv4.standard_id).toEqual(ipv4StandardId);
    expect(ipv4.x_opencti_stix_ids).toEqual([ipv4BundleId]);
    ipv4InternalId = ipv4.id;
  });

  it('should create the network traffic with its STIX 2.1 id and only its bundle id as other id', async () => {
    const networkTraffic = await importNetworkTraffic(networkTrafficBundleId, 50);
    expect(networkTraffic.standard_id).toEqual(networkTrafficStandardId);
    expect(networkTraffic.x_opencti_stix_ids).toEqual([networkTrafficBundleId]);
    networkTrafficInternalId = networkTraffic.id;
  });

  it('should resolve the same traffic from another bundle after the referenced IPv4 changed', async () => {
    await queryAsAdminWithSuccess({ query: EDIT_QUERY, variables: { id: ipv4InternalId, input: [{ key: 'x_opencti_score', value: [70] }] } });
    const networkTraffic = await importNetworkTraffic(otherNetworkTrafficBundleId, 50);
    expect(networkTraffic.id).toEqual(networkTrafficInternalId);
    expect(networkTraffic.standard_id).toEqual(networkTrafficStandardId);
    expect(networkTraffic.x_opencti_stix_ids).toEqual(expect.arrayContaining([networkTrafficBundleId, otherNetworkTrafficBundleId]));
  });

  it('should keep the standard id when the traffic is upserted with a non contributing change', async () => {
    const networkTraffic = await importNetworkTraffic(networkTrafficStandardId, 80);
    expect(networkTraffic.id).toEqual(networkTrafficInternalId);
    expect(networkTraffic.standard_id).toEqual(networkTrafficStandardId);
    expect(networkTraffic.x_opencti_score).toEqual(80);
    expect(networkTraffic.x_opencti_stix_ids).toEqual(expect.arrayContaining([networkTrafficBundleId, otherNetworkTrafficBundleId]));
  });

  it('should keep the previous ids when a contributing field is added', async () => {
    const result = await queryAsAdminWithSuccess({
      query: EDIT_QUERY,
      variables: { id: networkTrafficInternalId, input: [{ key: 'end', value: ['2026-11-18T12:00:00.000Z'] }] },
    });
    const networkTraffic = result.data.stixCyberObservableEdit.fieldPatch;
    expect(networkTraffic.standard_id).not.toEqual(networkTrafficStandardId);
    expect(networkTraffic.x_opencti_stix_ids).toEqual(expect.arrayContaining([networkTrafficStandardId, networkTrafficBundleId, otherNetworkTrafficBundleId]));
  });

  it('should resolve the first bundle again after the contributing field update', async () => {
    const networkTraffic = await importNetworkTraffic(networkTrafficBundleId, 80);
    expect(networkTraffic.id).toEqual(networkTrafficInternalId);
  });

  it('should delete the network traffic and the IPv4', async () => {
    await queryAsAdminWithSuccess({ query: DELETE_QUERY, variables: { id: networkTrafficInternalId } });
    await queryAsAdminWithSuccess({ query: DELETE_QUERY, variables: { id: ipv4InternalId } });
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: networkTrafficInternalId } });
    expect(queryResult.data.stixCyberObservable).toBeNull();
  });
});

describe('Software PURL', () => {
  const PURL = 'pkg:npm/lodash@4.17.21';
  let softwareInternalId;
  let softwareStandardId;

  const SOFTWARE_ADD_QUERY = gql`
    mutation SoftwarePurlAdd($type: String!, $Software: SoftwareAddInput) {
      stixCyberObservableAdd(type: $type, Software: $Software) {
        id
        standard_id
        ... on Software {
          name
          x_opencti_purl
        }
      }
    }
  `;
  const SOFTWARE_DELETE_QUERY = gql`
    mutation SoftwarePurlDelete($id: ID!) {
      stixCyberObservableEdit(id: $id) {
        delete
      }
    }
  `;

  it('should create a software with a purl', async () => {
    const result = await queryAsAdminWithSuccess({
      query: SOFTWARE_ADD_QUERY,
      variables: { type: 'Software', Software: { name: 'lodash-purl-test', vendor: 'lodash', version: '4.17.21', x_opencti_purl: PURL } },
    });
    const software = result.data.stixCyberObservableAdd;
    expect(software.x_opencti_purl).toEqual(PURL);
    softwareInternalId = software.id;
    softwareStandardId = software.standard_id;
  });

  it('should keep the purl out of the deterministic id', async () => {
    // Same contributing fields, another purl: the upsert resolves the same software
    const result = await queryAsAdminWithSuccess({
      query: SOFTWARE_ADD_QUERY,
      variables: { type: 'Software', Software: { name: 'lodash-purl-test', vendor: 'lodash', version: '4.17.21', x_opencti_purl: 'pkg:npm/lodash@4.17.21?repository_url=example' } },
    });
    expect(result.data.stixCyberObservableAdd.id).toEqual(softwareInternalId);
    expect(result.data.stixCyberObservableAdd.standard_id).toEqual(softwareStandardId);
  });

  it('should export the purl as a custom property of the OpenCTI extension', async () => {
    const queryResult = await queryAsAdminWithSuccess({ query: READ_QUERY, variables: { id: softwareInternalId } });
    const stix = JSON.parse(queryResult.data.stixCyberObservable.toStix);
    const extension = Object.values(stix.extensions).find((ext) => ext.extension_type === 'property-extension' && ext.purl !== undefined);
    expect(extension).toBeDefined();
    expect(extension.purl).toMatch(/^pkg:npm\/lodash@4\.17\.21/);
  });

  it('should filter softwares by purl', async () => {
    const queryResult = await queryAsAdminWithSuccess({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [{ key: 'x_opencti_purl', values: ['pkg:npm/lodash@4.17.21?repository_url=example'] }],
          filterGroups: [],
        },
      },
    });
    const ids = queryResult.data.stixCyberObservables.edges.map((edge) => edge.node.id);
    expect(ids).toEqual([softwareInternalId]);
  });

  it('should delete the software', async () => {
    await queryAsAdminWithSuccess({ query: SOFTWARE_DELETE_QUERY, variables: { id: softwareInternalId } });
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: softwareInternalId } });
    expect(queryResult.data.stixCyberObservable).toBeNull();
  });
});

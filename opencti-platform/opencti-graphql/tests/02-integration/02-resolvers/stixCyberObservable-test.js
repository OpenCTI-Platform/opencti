import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { internalAdminQuery, queryAsAdmin } from '../../utils/testQuery';

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
  it('should stixCyberObservable created', async () => {
    const CREATE_QUERY = gql`
            mutation StixCyberObservableAdd($type: String!, $IPv4Addr: IPv4AddrAddInput) {
                stixCyberObservableAdd(type: $type, IPv4Addr: $IPv4Addr) {
                    id
                    observable_value
                    ... on IPv4Addr {
                        value
                    }
                }
            }
        `;
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
    const CREATE_QUERY = gql`
            mutation StixCyberObservableAdd($type: String!, $NetworkTraffic: NetworkTrafficAddInput) {
                stixCyberObservableAdd(type: $type, NetworkTraffic: $NetworkTraffic) {
                    id
                    observable_value
                    ... on NetworkTraffic {
                        dst_port
                    }
                }
            }
        `;
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
  it('should stixCyberObservable loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixCyberObservableInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixCyberObservable).not.toBeNull();
    expect(queryResult.data.stixCyberObservable.id).toEqual(stixCyberObservableInternalId);
    expect(queryResult.data.stixCyberObservable.toStix.length).toBeGreaterThan(5);
  });
  it('should list stixCyberObservables', async () => {
    const queryResult = await queryAsAdmin({ query: gql(LIST_QUERY), variables: { first: 10 } });
    expect(queryResult.data.stixCyberObservables.edges.length).toEqual(7);
  });
  it('should list stixCyberObservables orderBy observable_value', async () => {
    const queryResult = await internalAdminQuery(LIST_QUERY, { first: 10, orderBy: 'observable_value', orderMode: 'desc' });
    expect(queryResult.data.stixCyberObservables).not.toBeNull();
    expect(queryResult.data.stixCyberObservables.edges.length).toEqual(6);
  });
  it('should update stixCyberObservable', async () => {
    const UPDATE_QUERY = gql`
            mutation StixCyberObservableEdit($id: ID!, $input: [EditInput]!) {
                stixCyberObservableEdit(id: $id) {
                    fieldPatch(input: $input) {
                        id
                        x_opencti_score
                    }
                }
            }
        `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: {
        id: stixCyberObservableInternalId,
        input: { key: 'x_opencti_score', value: '20' },
      },
    });
    expect(queryResult.data.stixCyberObservableEdit.fieldPatch.x_opencti_score).toEqual(20);
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
    const CREATE_QUERY = gql`
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
      query: CREATE_QUERY,
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

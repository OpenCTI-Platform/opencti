import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query stixCyberObservables(
    $first: Int
    $after: ID
    $orderBy: StixCyberObservablesOrdering
    $orderMode: OrderingMode
    $filters: [StixCyberObservablesFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    stixCyberObservables(
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      filterMode: $filterMode
      search: $search
    ) {
      edges {
        node {
          id
          observable_value
          description
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
      description
      toStix
    }
  }
`;

describe('StixCyberObservable resolver standard behavior', () => {
  let stixCyberObservableInternalId;
  let stixCyberObservableMarkingDefinitionRelationId;
  const stixCyberObservableStixId = 'ipv4-addr--921c202b-5706-499d-9484-b5cf9bc6f70c';
  it('should stixCyberObservable created', async () => {
    const CREATE_QUERY = gql`
      mutation StixCyberObservableAdd($input: StixCyberObservableAddInput) {
        stixCyberObservableAdd(input: $input) {
          id
          observable_value
          description
        }
      }
    `;
    // Create the stixCyberObservable
    const STIX_OBSERVABLE_TO_CREATE = {
      input: {
        type: 'IPv4-Addr',
        observable_value: '8.8.8.8',
        stix_id_key: stixCyberObservableStixId,
        description: 'StixCyberObservable description',
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
  it('should stixCyberObservable loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixCyberObservableInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixCyberObservable).not.toBeNull();
    expect(queryResult.data.stixCyberObservable.id).toEqual(stixCyberObservableInternalId);
    expect(queryResult.data.stixCyberObservable.toStix.length).toBeGreaterThan(5);
  });
  it('should list stixCyberObservables', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.stixCyberObservables.edges.length).toEqual(7);
  });
  it('should update stixCyberObservable', async () => {
    const UPDATE_QUERY = gql`
      mutation StixCyberObservableEdit($id: ID!, $input: EditInput!) {
        stixCyberObservableEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            description
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: stixCyberObservableInternalId, input: { key: 'description', value: ['StixCyberObservable - test'] } },
    });
    expect(queryResult.data.stixCyberObservableEdit.fieldPatch.description).toEqual('StixCyberObservable - test');
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
      mutation StixCyberObservableEdit($id: ID!, $input: RelationAddInput!) {
        stixCyberObservableEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on StixCyberObservable {
                markingDefinitions {
                  edges {
                    node {
                      id
                    }
                    relation {
                      id
                    }
                  }
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
          toId: '43f586bc-bcbc-43d1-ab46-43e5ab1a2c46',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.stixCyberObservableEdit.relationAdd.from.objectMarking.edges.length).toEqual(1);
    stixCyberObservableMarkingDefinitionRelationId =
      queryResult.data.stixCyberObservableEdit.relationAdd.from.objectMarking.edges[0].relation.id;
  });
  it('should delete relation in stixCyberObservable', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation StixCyberObservableEdit($id: ID!, $relationId: ID!) {
        stixCyberObservableEdit(id: $id) {
          relationDelete(relationId: $relationId) {
            id
            markingDefinitions {
              edges {
                node {
                  id
                }
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: stixCyberObservableInternalId,
        relationId: stixCyberObservableMarkingDefinitionRelationId,
      },
    });
    expect(queryResult.data.stixCyberObservableEdit.relationDelete.objectMarking.edges.length).toEqual(0);
  });
  it('should add observable in note', async () => {
    const CREATE_QUERY = gql`
      mutation NoteAdd($input: NoteAddInput) {
        noteAdd(input: $input) {
          id
          name
          description
          content
        }
      }
    `;
    // Create the note
    const NOTE_TO_CREATE = {
      input: {
        name: 'Note',
        description: 'Note description',
        content: 'Test content',
        observableRefs: [stixCyberObservableInternalId],
      },
    };
    const note = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: NOTE_TO_CREATE,
    });
    expect(note).not.toBeNull();
    expect(note.data.noteAdd).not.toBeNull();
    expect(note.data.noteAdd.name).toEqual('Note');
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
          name
          description
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
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixCyberObservableStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixCyberObservable).toBeNull();
  });
});

import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query stixObservables(
    $first: Int
    $after: ID
    $orderBy: StixObservablesOrdering
    $orderMode: OrderingMode
    $filters: [StixObservablesFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    stixObservables(
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
  query stixObservable($id: String!) {
    stixObservable(id: $id) {
      id
      observable_value
      description
      toStix
    }
  }
`;

describe('StixObservable resolver standard behavior', () => {
  let stixObservableInternalId;
  let stixObservableMarkingDefinitionRelationId;
  const stixObservableStixId = 'ipv4-addr--921c202b-5706-499d-9484-b5cf9bc6f70c';
  it('should stixObservable created', async () => {
    const CREATE_QUERY = gql`
      mutation StixObservableAdd($input: StixObservableAddInput) {
        stixObservableAdd(input: $input) {
          id
          observable_value
          description
        }
      }
    `;
    // Create the stixObservable
    const STIX_OBSERVABLE_TO_CREATE = {
      input: {
        type: 'IPv4-Addr',
        observable_value: '8.8.8.8',
        stix_id_key: stixObservableStixId,
        description: 'StixObservable description',
      },
    };
    const stixObservable = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: STIX_OBSERVABLE_TO_CREATE,
    });
    expect(stixObservable).not.toBeNull();
    expect(stixObservable.data.stixObservableAdd).not.toBeNull();
    expect(stixObservable.data.stixObservableAdd.observable_value).toEqual('8.8.8.8');
    stixObservableInternalId = stixObservable.data.stixObservableAdd.id;
  });
  it('should stixObservable loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixObservableInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixObservable).not.toBeNull();
    expect(queryResult.data.stixObservable.id).toEqual(stixObservableInternalId);
    expect(queryResult.data.stixObservable.toStix.length).toBeGreaterThan(5);
  });
  it('should list stixObservables', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.stixObservables.edges.length).toEqual(7);
  });
  it('should update stixObservable', async () => {
    const UPDATE_QUERY = gql`
      mutation StixObservableEdit($id: ID!, $input: EditInput!) {
        stixObservableEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            description
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: stixObservableInternalId, input: { key: 'description', value: ['StixObservable - test'] } },
    });
    expect(queryResult.data.stixObservableEdit.fieldPatch.description).toEqual('StixObservable - test');
  });
  it('should context patch stixObservable', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation StixObservableEdit($id: ID!, $input: EditContext) {
        stixObservableEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: stixObservableInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.stixObservableEdit.contextPatch.id).toEqual(stixObservableInternalId);
  });
  it('should context clean stixObservable', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation StixObservableEdit($id: ID!) {
        stixObservableEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: stixObservableInternalId },
    });
    expect(queryResult.data.stixObservableEdit.contextClean.id).toEqual(stixObservableInternalId);
  });
  it('should add relation in stixObservable', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation StixObservableEdit($id: ID!, $input: RelationAddInput!) {
        stixObservableEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on StixObservable {
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
        id: stixObservableInternalId,
        input: {
          fromRole: 'so',
          toRole: 'marking',
          toId: '43f586bc-bcbc-43d1-ab46-43e5ab1a2c46',
          through: 'object_marking_refs',
        },
      },
    });
    expect(queryResult.data.stixObservableEdit.relationAdd.from.markingDefinitions.edges.length).toEqual(1);
    stixObservableMarkingDefinitionRelationId =
      queryResult.data.stixObservableEdit.relationAdd.from.markingDefinitions.edges[0].relation.id;
  });
  it('should delete relation in stixObservable', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation StixObservableEdit($id: ID!, $relationId: ID!) {
        stixObservableEdit(id: $id) {
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
        id: stixObservableInternalId,
        relationId: stixObservableMarkingDefinitionRelationId,
      },
    });
    expect(queryResult.data.stixObservableEdit.relationDelete.markingDefinitions.edges.length).toEqual(0);
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
        observableRefs: [stixObservableInternalId],
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
  it('should stixObservable deleted', async () => {
    const DELETE_QUERY = gql`
      mutation stixObservableDelete($id: ID!) {
        stixObservableEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the stixObservable
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: stixObservableInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixObservableStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixObservable).toBeNull();
  });
});

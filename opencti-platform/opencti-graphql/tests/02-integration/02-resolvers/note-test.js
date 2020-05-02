import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
import { now } from '../../../src/database/grakn';

const LIST_QUERY = gql`
  query notes(
    $first: Int
    $after: ID
    $orderBy: NotesOrdering
    $orderMode: OrderingMode
    $filters: [NotesFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    notes(
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
          name
          description
          content
        }
      }
    }
  }
`;

const TIMESERIES_QUERY = gql`
  query notesTimeSeries(
    $objectId: String
    $authorId: String
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
  ) {
    notesTimeSeries(
      objectId: $objectId
      authorId: $authorId
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      interval: $interval
    ) {
      date
      value
    }
  }
`;

const NUMBER_QUERY = gql`
  query notesNumber($objectId: String, $endDate: DateTime!) {
    notesNumber(objectId: $objectId, endDate: $endDate) {
      total
      count
    }
  }
`;

const DISTRIBUTION_QUERY = gql`
  query notesDistribution(
    $objectId: String
    $field: String!
    $operation: StatsOperation!
    $limit: Int
    $order: String
  ) {
    notesDistribution(objectId: $objectId, field: $field, operation: $operation, limit: $limit, order: $order) {
      label
      value
    }
  }
`;

const READ_QUERY = gql`
  query note($id: String!) {
    note(id: $id) {
      id
      name
      description
      toStix
    }
  }
`;

describe('Note resolver standard behavior', () => {
  let noteInternalId;
  let noteMarkingDefinitionRelationId;
  const noteStixId = 'note--2cf49568-b812-45fe-8c48-bb0c7d5eb952';
  it('should note created', async () => {
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
        stix_id_key: noteStixId,
        description: 'Note description',
        content: 'Test content',
        objectRefs: ['fab6fa99-b07f-4278-86b4-b674edf60877'],
        relationRefs: ['209cbdf0-fc5e-47c9-8023-dd724993ae55'],
      },
    };
    const note = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: NOTE_TO_CREATE,
    });
    expect(note).not.toBeNull();
    expect(note.data.noteAdd).not.toBeNull();
    expect(note.data.noteAdd.name).toEqual('Note');
    noteInternalId = note.data.noteAdd.id;
  });
  it('should note loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: noteInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.note).not.toBeNull();
    expect(queryResult.data.note.id).toEqual(noteInternalId);
    expect(queryResult.data.note.toStix.length).toBeGreaterThan(5);
  });
  it('should note loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: noteStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.note).not.toBeNull();
    expect(queryResult.data.note.id).toEqual(noteInternalId);
  });
  it('should note stix domain entities accurate', async () => {
    const NOTE_STIX_DOMAIN_ENTITIES = gql`
      query note($id: String!) {
        note(id: $id) {
          id
          objectRefs {
            edges {
              node {
                id
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: NOTE_STIX_DOMAIN_ENTITIES,
      variables: { id: 'ce216266-4962-4b5a-9e48-cdf3453f5281' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.note).not.toBeNull();
    expect(queryResult.data.note.id).toEqual('ce216266-4962-4b5a-9e48-cdf3453f5281');
    expect(queryResult.data.note.objectRefs.edges.length).toEqual(3);
  });
  it('should note contains stix domain entity accurate', async () => {
    const NOTE_CONTAINS_STIX_DOMAIN_ENTITY = gql`
      query noteContainsStixDomainEntity($id: String!, $objectId: String!) {
        noteContainsStixDomainEntity(id: $id, objectId: $objectId)
      }
    `;
    const queryResult = await queryAsAdmin({
      query: NOTE_CONTAINS_STIX_DOMAIN_ENTITY,
      variables: { id: 'ce216266-4962-4b5a-9e48-cdf3453f5281', objectId: '82316ffd-a0ec-4519-a454-6566f8f5676c' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.noteContainsStixDomainEntity).not.toBeNull();
    expect(queryResult.data.noteContainsStixDomainEntity).toBeTruthy();
  });
  it('should note stix relations accurate', async () => {
    const NOTE_STIX_RELATIONS = gql`
      query note($id: String!) {
        note(id: $id) {
          id
          relationRefs {
            edges {
              node {
                id
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: NOTE_STIX_RELATIONS,
      variables: { id: 'ce216266-4962-4b5a-9e48-cdf3453f5281' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.note).not.toBeNull();
    expect(queryResult.data.note.id).toEqual('ce216266-4962-4b5a-9e48-cdf3453f5281');
    expect(queryResult.data.note.relationRefs.edges.length).toEqual(1);
  });
  it('should note contains stix relation accurate', async () => {
    const NOTE_CONTAINS_STIX_RELATION = gql`
      query noteContainsStixRelation($id: String!, $objectId: String!) {
        noteContainsStixRelation(id: $id, objectId: $objectId)
      }
    `;
    const queryResult = await queryAsAdmin({
      query: NOTE_CONTAINS_STIX_RELATION,
      variables: { id: 'ce216266-4962-4b5a-9e48-cdf3453f5281', objectId: '97ebc9b3-8a25-428a-8523-1e87b2701d3d' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.noteContainsStixRelation).not.toBeNull();
    expect(queryResult.data.noteContainsStixRelation).toBeTruthy();
  });
  it('should note stix observables accurate', async () => {
    const NOTE_STIX_OBSERVABLES = gql`
      query note($id: String!) {
        note(id: $id) {
          id
          observableRefs {
            edges {
              node {
                id
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: NOTE_STIX_OBSERVABLES,
      variables: { id: 'ce216266-4962-4b5a-9e48-cdf3453f5281' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.note).not.toBeNull();
    expect(queryResult.data.note.id).toEqual('ce216266-4962-4b5a-9e48-cdf3453f5281');
    expect(queryResult.data.note.observableRefs.edges.length).toEqual(3);
  });
  it('should list notes', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.notes.edges.length).toEqual(2);
  });
  it('should timeseries notes to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: TIMESERIES_QUERY,
      variables: {
        field: 'created',
        operation: 'count',
        startDate: '2020-01-01T00:00:00+00:00',
        endDate: '2021-01-01T00:00:00+00:00',
        interval: 'month',
      },
    });
    expect(queryResult.data.notesTimeSeries.length).toEqual(13);
    expect(queryResult.data.notesTimeSeries[2].value).toEqual(1);
    expect(queryResult.data.notesTimeSeries[3].value).toEqual(0);
  });
  it('should timeseries notes for entity to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: TIMESERIES_QUERY,
      variables: {
        objectId: 'ab78a62f-4928-4d5a-8740-03f0af9c4330',
        field: 'created',
        operation: 'count',
        startDate: '2020-01-01T00:00:00+00:00',
        endDate: '2021-01-01T00:00:00+00:00',
        interval: 'month',
      },
    });
    expect(queryResult.data.notesTimeSeries.length).toEqual(13);
    expect(queryResult.data.notesTimeSeries[2].value).toEqual(1);
    expect(queryResult.data.notesTimeSeries[3].value).toEqual(0);
  });
  it('should timeseries notes for author to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: TIMESERIES_QUERY,
      variables: {
        authorId: 'c79e5d9f-4321-4174-b120-7cd9342ec88a',
        field: 'created',
        operation: 'count',
        startDate: '2020-01-01T00:00:00+00:00',
        endDate: '2021-01-01T00:00:00+00:00',
        interval: 'month',
      },
    });
    expect(queryResult.data.notesTimeSeries.length).toEqual(13);
    expect(queryResult.data.notesTimeSeries[2].value).toEqual(1);
    expect(queryResult.data.notesTimeSeries[3].value).toEqual(0);
  });
  it('should notes number to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: NUMBER_QUERY,
      variables: {
        endDate: now(),
      },
    });
    expect(queryResult.data.notesNumber.total).toEqual(2);
    expect(queryResult.data.notesNumber.count).toEqual(2);
  });
  it('should notes number by entity to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: NUMBER_QUERY,
      variables: {
        objectId: 'ab78a62f-4928-4d5a-8740-03f0af9c4330',
        endDate: now(),
      },
    });
    expect(queryResult.data.notesNumber.total).toEqual(1);
    expect(queryResult.data.notesNumber.count).toEqual(1);
  });
  it('should notes distribution to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: DISTRIBUTION_QUERY,
      variables: {
        field: 'created_by_ref.name',
        operation: 'count',
      },
    });
    expect(queryResult.data.notesDistribution.length).toEqual(0);
  });
  it('should notes distribution by entity to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: DISTRIBUTION_QUERY,
      variables: {
        objectId: 'ab78a62f-4928-4d5a-8740-03f0af9c4330',
        field: 'created_by_ref.name',
        operation: 'count',
      },
    });
    expect(queryResult.data.notesDistribution[0].label).toEqual('ANSSI');
    expect(queryResult.data.notesDistribution[0].value).toEqual(1);
  });
  it('should update note', async () => {
    const UPDATE_QUERY = gql`
      mutation NoteEdit($id: ID!, $input: EditInput!) {
        noteEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: noteInternalId, input: { key: 'name', value: ['Note - test'] } },
    });
    expect(queryResult.data.noteEdit.fieldPatch.name).toEqual('Note - test');
  });
  it('should context patch note', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation NoteEdit($id: ID!, $input: EditContext) {
        noteEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: noteInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.noteEdit.contextPatch.id).toEqual(noteInternalId);
  });
  it('should context clean note', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation NoteEdit($id: ID!) {
        noteEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: noteInternalId },
    });
    expect(queryResult.data.noteEdit.contextClean.id).toEqual(noteInternalId);
  });
  it('should add relation in note', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation NoteEdit($id: ID!, $input: RelationAddInput!) {
        noteEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on Note {
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
        id: noteInternalId,
        input: {
          fromRole: 'so',
          toRole: 'marking',
          toId: '43f586bc-bcbc-43d1-ab46-43e5ab1a2c46',
          through: 'object_marking_refs',
        },
      },
    });
    expect(queryResult.data.noteEdit.relationAdd.from.markingDefinitions.edges.length).toEqual(1);
    noteMarkingDefinitionRelationId =
      queryResult.data.noteEdit.relationAdd.from.markingDefinitions.edges[0].relation.id;
  });
  it('should delete relation in note', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation NoteEdit($id: ID!, $relationId: ID!) {
        noteEdit(id: $id) {
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
        id: noteInternalId,
        relationId: noteMarkingDefinitionRelationId,
      },
    });
    expect(queryResult.data.noteEdit.relationDelete.markingDefinitions.edges.length).toEqual(0);
  });
  it('should note deleted', async () => {
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
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: noteStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.note).toBeNull();
  });
});

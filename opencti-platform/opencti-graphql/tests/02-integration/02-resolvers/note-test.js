import gql from 'graphql-tag';
import { ADMIN_USER, queryAsAdmin } from '../../utils/testQuery';
import { elLoadById } from '../../../src/database/engine';
import { now } from '../../../src/utils/format';

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
          attribute_abstract
          content
          authors
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
      entity {
        ... on Identity {
          name
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query note($id: String!) {
    note(id: $id) {
      id
      standard_id
      attribute_abstract
      content
      authors
      toStix
    }
  }
`;

describe('Note resolver standard behavior', () => {
  let noteInternalId;
  let datasetNoteInternalId;
  const noteStixId = 'note--2cf49568-b812-45fe-8c48-bb0c7d5eb952';
  it('should note created', async () => {
    const CREATE_QUERY = gql`
      mutation NoteAdd($input: NoteAddInput) {
        noteAdd(input: $input) {
          id
          standard_id
          attribute_abstract
          content
          authors
        }
      }
    `;
    // Create the note
    const NOTE_TO_CREATE = {
      input: {
        stix_id: noteStixId,
        attribute_abstract: 'Note',
        content: 'Test content',
        objects: [
          'campaign--92d46985-17a6-4610-8be8-cc70c82ed214',
          'relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02',
        ],
        createdBy: 'identity--7b82b010-b1c0-4dae-981f-7756374a17df',
      },
    };
    const note = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: NOTE_TO_CREATE,
    });
    expect(note).not.toBeNull();
    expect(note.data.noteAdd).not.toBeNull();
    expect(note.data.noteAdd.attribute_abstract).toEqual('Note');
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
  it('should note stix objects or stix relationships accurate', async () => {
    const note = await elLoadById(ADMIN_USER, 'note--573f623c-bf68-4f19-9500-d618f0d00af0');
    datasetNoteInternalId = note.internal_id;
    const NOTE_STIX_DOMAIN_ENTITIES = gql`
      query note($id: String!) {
        note(id: $id) {
          id
          standard_id
          objects {
            edges {
              node {
                ... on BasicObject {
                  id
                  standard_id
                }
                ... on BasicRelationship {
                  id
                  standard_id
                }
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: NOTE_STIX_DOMAIN_ENTITIES,
      variables: { id: datasetNoteInternalId },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.note).not.toBeNull();
    expect(queryResult.data.note.objects.edges.length).toEqual(5);
  });
  it('should note contains stix object or stix relationship accurate', async () => {
    const intrusionSet = await elLoadById(ADMIN_USER, 'intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7');
    const stixRelationship = await elLoadById(ADMIN_USER, 'relationship--9f999fc5-5c74-4964-ab87-ee4c7cdc37a3');
    const NOTE_CONTAINS_STIX_OBJECT_OR_STIX_RELATIONSHIP = gql`
      query noteContainsStixObjectOrStixRelationship($id: String!, $stixObjectOrStixRelationshipId: String!) {
        noteContainsStixObjectOrStixRelationship(
          id: $id
          stixObjectOrStixRelationshipId: $stixObjectOrStixRelationshipId
        )
      }
    `;
    let queryResult = await queryAsAdmin({
      query: NOTE_CONTAINS_STIX_OBJECT_OR_STIX_RELATIONSHIP,
      variables: {
        id: datasetNoteInternalId,
        stixObjectOrStixRelationshipId: intrusionSet.internal_id,
      },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.noteContainsStixObjectOrStixRelationship).not.toBeNull();
    expect(queryResult.data.noteContainsStixObjectOrStixRelationship).toBeTruthy();
    queryResult = await queryAsAdmin({
      query: NOTE_CONTAINS_STIX_OBJECT_OR_STIX_RELATIONSHIP,
      variables: {
        id: datasetNoteInternalId,
        stixObjectOrStixRelationshipId: stixRelationship.internal_id,
      },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.noteContainsStixObjectOrStixRelationship).not.toBeNull();
    expect(queryResult.data.noteContainsStixObjectOrStixRelationship).toBeTruthy();
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
    const malware = await elLoadById(ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const queryResult = await queryAsAdmin({
      query: TIMESERIES_QUERY,
      variables: {
        objectId: malware.internal_id,
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
    const identity = await elLoadById(ADMIN_USER, 'identity--7b82b010-b1c0-4dae-981f-7756374a17df');
    const queryResult = await queryAsAdmin({
      query: TIMESERIES_QUERY,
      variables: {
        authorId: identity.internal_id,
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
    const malware = await elLoadById(ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const queryResult = await queryAsAdmin({
      query: NUMBER_QUERY,
      variables: {
        objectId: malware.internal_id,
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
        field: 'created-by.name',
        operation: 'count',
      },
    });
    expect(queryResult.data.notesDistribution.length).toEqual(0);
  });
  it('should notes distribution by entity to be accurate', async () => {
    const malware = await elLoadById(ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const queryResult = await queryAsAdmin({
      query: DISTRIBUTION_QUERY,
      variables: {
        objectId: malware.internal_id,
        field: 'created-by.internal_id',
        operation: 'count',
      },
    });
    expect(queryResult.data.notesDistribution[0].entity.name).toEqual('ANSSI');
    expect(queryResult.data.notesDistribution[0].value).toEqual(1);
  });
  it('should update note', async () => {
    const UPDATE_QUERY = gql`
      mutation NoteEdit($id: ID!, $input: [EditInput]!) {
        noteEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            attribute_abstract
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: noteInternalId, input: { key: 'attribute_abstract', value: ['Note - test'] } },
    });
    expect(queryResult.data.noteEdit.fieldPatch.attribute_abstract).toEqual('Note - test');
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
      mutation NoteEdit($id: ID!, $input: StixMetaRelationshipAddInput!) {
        noteEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on Note {
                objectMarking {
                  edges {
                    node {
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
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.noteEdit.relationAdd.from.objectMarking.edges.length).toEqual(1);
  });
  it('should delete relation in note', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation NoteEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        noteEdit(id: $id) {
          relationDelete(toId: $toId, relationship_type: $relationship_type) {
            id
            objectMarking {
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
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.noteEdit.relationDelete.objectMarking.edges.length).toEqual(0);
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

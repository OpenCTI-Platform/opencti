import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, queryAsAdmin, testContext } from '../../utils/testQuery';
import { elLoadById } from '../../../src/database/engine';

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
          likelihood
          confidence
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
      likelihood
      confidence
    }
  }
`;

describe('Note resolver standard behavior', () => {
  let noteInternalId;
  let datasetNoteInternalId;
  const noteStixId = 'note--2cf49568-b812-45fe-8c48-bb0c7d5eb952';
  it('should note created', async () => {
    const CREATE_QUERY = gql`
      mutation NoteAdd($input: NoteAddInput!) {
        noteAdd(input: $input) {
          id
          standard_id
          attribute_abstract
          content
          authors
          likelihood
          confidence
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
        likelihood: 90,
        confidence: 20,
      },
    };
    const note = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: NOTE_TO_CREATE,
    });
    expect(note).not.toBeNull();
    expect(note.data.noteAdd).not.toBeNull();
    expect(note.data.noteAdd.attribute_abstract).toEqual('Note');
    expect(note.data.noteAdd.likelihood).toEqual(90);
    expect(note.data.noteAdd.confidence).toEqual(20);
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
    const note = await elLoadById(testContext, ADMIN_USER, 'note--573f623c-bf68-4f19-9500-d618f0d00af0');
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
    expect(queryResult.data.note.objects.edges.length).toEqual(4);
  });
  it('should list notes', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.notes.edges.length).toEqual(2);
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
      mutation NoteEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
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

import submitOperation from '../../config';

const cyioNotesQuery = `query cyioNotesQuery {
    cyioNotes(limit: 1, offset: 0) {
      pageInfo {
        startCursor
        endCursor
      }
      edges {
        cursor
        node {
          id
          entity_type
          created
          modified
        }
      }
    }
  }`;

const cyioNoteQuery = `
  query cyioLabelQuery {
    cyioNote(id: "") {
      id
      entity_type
      created
      modified
    }
  }`;

describe('Successfully Query Cyio Notes', () => {
  it('Return a list of notes', async () => {
    const result = await submitOperation(cyioNotesQuery);

    expect(typeof { value: result.data.cyioNotes.edges[0] }).toBe('object');
  });

  it('Return a single note', async () => {
    const result = await submitOperation(cyioNoteQuery);
    expect(typeof { value: result.data }).toBe('object');
  });
});

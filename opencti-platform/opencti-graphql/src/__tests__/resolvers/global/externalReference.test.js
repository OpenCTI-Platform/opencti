import submitOperation from '../../config';

const cyioExternalReferencesQuery = `query cyioExternalReferencesQuery {
    cyioExternalReferences(limit: 1, offset: 0) {
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

const cyioExternalReferenceQuery = `
  query cyioExternalReferenceQuery {
    cyioExternalReference(id: "") {
      id
      entity_type
      created
      modified
    }
  }`;

describe('Successfully Query Cyio External References', () => {
  it('Return a list of external references', async () => {
    const result = await submitOperation(cyioExternalReferencesQuery);

    expect(typeof { value: result.data.cyioExternalRefefrences.edges[0] }).toBe('object');
  });

  it('Return a single note', async () => {
    const result = await submitOperation(cyioExternalReferenceQuery);
    expect(typeof { value: result.data }).toBe('object');
  });
});

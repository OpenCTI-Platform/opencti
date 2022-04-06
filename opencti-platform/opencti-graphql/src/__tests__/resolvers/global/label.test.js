import submitOperation from '../../config';

const cyioLabelsQuery = `query cyioLabelsQuery {
    cyioLabels(limit: 1, offset: 0) {
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

const cyioLabelQuery = `
  query cyioLabelQuery {
    cyioLabel(id: "4e0fc443-78de-559f-97d3-6f9019666cec") {
      id
      entity_type
      created
      modified
    }
  }`;

describe('Successfully Query Cyio Labels', () => {
  it('Return a list of labels', async () => {
    const result = await submitOperation(cyioLabelsQuery);

    expect(typeof { value: result.data.cyioLabels.edges[0] }).toBe('object');
  });

  it('Return a single label', async () => {
    const result = await submitOperation(cyioLabelQuery);
    expect(typeof { value: result.data }).toBe('object');
  });
});

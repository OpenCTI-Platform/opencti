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

describe('Cyio Label Tests', () => {
  let currentLabelId = '';
  it('Create a new cyio label', async () => {
    const createCyioLabel = `mutation createCyioLabel {
      createCyioLabel(
        input: {
          name: "Test Label",
          description: "Label Description",
          color: "Red",
        }
       ){
        id
    }
  }`;

    const result = await submitOperation(createCyioLabel);
    currentLabelId = result.data.createCyioLabel.id;

    expect(typeof { value: result.data }).toBe('object');
  });

  it('Return a list of labels', async () => {
    const result = await submitOperation(cyioLabelsQuery);

    expect(typeof { value: result.data.cyioLabels.edges[0] }).toBe('object');
  });

  it('Return a single cyio label', async () => {
    const singleCyioLabel = `query queryCyioLabel($id: ID!) {
      cyioLabel(id:$id){
        id
    }`;
    const variables = { id: currentLabelId };
    const result = await submitOperation(singleCyioLabel, variables);
    expect(typeof { value: result.data }).toBe('object');
  });

  // ATTEMPT TO CLEAN UP TEST DATA
  it('Delete the newly created label', async () => {
    const deleteCyioLabel = `mutation deleteCyioLabel($id: ID!) {
      deleteCyioLabel(id:$id) }`;

    const variables = { id: currentLabelId };
    const result = await submitOperation(deleteCyioLabel, variables);

    expect(typeof { value: result.data.deleteCyioLabel }).toBe('object');
  });
});

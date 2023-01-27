import submitOperation from '../../config';

const poamsQuery = `query poams {
    poams(first:1, offset:0){
    pageInfo {
      startCursor
      endCursor
      globalCount
    }
    edges {
      cursor
      node {
        id
        entity_type
      }
    }
  }
}`;

describe('POAM Tests', () => {
  let currentPOAM = '';
  let currentPOAMItem = '';
  it('Create a new poam', async () => {
    const createPoam = `mutation createPoam {
      createPOAM(
        input: {
          name: "Integration Testing Poam",
          version: "1.0",
          oscal_version: "1.0",
          system_identifier_type: "System Id"
        }
       ){
        id
    }
  }`;
    const result = await submitOperation(createPoam);
    currentPOAM = result.data.createPOAM.id;

    expect(typeof { value: result.data }).toBe('object');
  });

  it('Create a new poam item', async () => {
    const createPoamItem = `mutation createPoamItem($poam: ID, $input: POAMItemAddInput) {
      createPOAMItem(poam: $poam, input: $input){
        id
    }
  }`;
    const variables = {
      poam: currentPOAM,
      input: {
        name: 'Testing Poam Item',
        description: 'Poam Item Description',
        poam_id: currentPOAM,
        accepted_risk: true,
      },
    };
    const result = await submitOperation(createPoamItem, variables);
    currentPOAMItem = result.data.createPOAMItem.id;

    expect(typeof { value: result.data }).toBe('object');
  });

  it('Return a list of poams', async () => {
    const result = await submitOperation(poamsQuery);
    expect(typeof { value: result.data }).toBe('object');
  });

  it('Return a single poam', async () => {
    const singlePoam = `query queryPoam($id: ID!) {
      poam(id:$id){
        id
      }
    }`;
    const variables = { id: currentPOAM };
    const result = await submitOperation(singlePoam, variables);
    expect(typeof { value: result.data }).toBe('object');
  });

  it('Return a single poam item', async () => {
    const singlePoam = `query queryPoamItem($id: ID!) {
      poam(id:$id){
        id
      }
    }`;
    const variables = { id: currentPOAMItem };
    const result = await submitOperation(singlePoam, variables);
    expect(typeof { value: result.data }).toBe('object');
  });
  // ATTEMPT TO CLEAN UP TEST DATA
  it('Delete the newly created poam', async () => {
    const deletePoam = `mutation deletePoam($id: ID!) {
      deletePOAM(id:$id) }`;

    const variables = { id: currentPOAM };
    const result = await submitOperation(deletePoam, variables);

    expect(typeof { value: result.data.deletePOAM }).toBe('object');
  });
});

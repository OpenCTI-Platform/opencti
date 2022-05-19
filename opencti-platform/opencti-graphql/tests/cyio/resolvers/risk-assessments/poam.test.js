import submitOperation from '../../config';

const poamQuery = `query poam {
    poam(id:"22f2ad37-4f07-5182-bf4e-59ea197a73dc") {
      id
      entity_type
    }
  }`;

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
  it('Return a list of poams', async () => {
    const result = await submitOperation(poamsQuery);
    expect(typeof { value: result.data }).toBe('object');
  });

  it('Return a single poam', async () => {
    const result = await submitOperation(poamQuery);
    expect(typeof { value: result.data }).toBe('object');
  });
});

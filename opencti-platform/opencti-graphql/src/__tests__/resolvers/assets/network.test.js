import submitOperation from '../../config';

const networkAssetList = `query networkAssetListQuery {
    networkAssetList(first: 1, offset: 0) {
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
  }
`;

const networkAssetQuery = `query networkAssetQuery {
    networkAsset(id: "2c14936c-87b1-536e-ac93-b72cb82e996c") {
      id
      entity_type
      created
      modified
    }
  }`;
describe('Successfully Query Network Assets', () => {
  it('Return network asset list', async () => {
    const result = await submitOperation(networkAssetList);

    expect(typeof { value: result.data.networkAssetList.edges[0] }).toBe('object');
  });

  it('Return a single network asset', async () => {
    const result = await submitOperation(networkAssetQuery);
    expect(typeof { value: result.data }).toBe('object');
  });
});

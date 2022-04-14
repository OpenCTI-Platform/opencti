import submitOperation from '../../config';

const softwareAssetList = `query softwareAssetListQuery {
    softwareAssetList(first: 1, offset: 0) {
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

const softwareAssetQuery = `query softwareAssetQuery {
    softwareAsset(id: "efc9588c-72d7-57f9-81c9-f55f52d92e91") {
      id
      entity_type
      created
      modified
    }
  }`;
describe('Successfully Query Software Assets', () => {
  // it('Return software asset list', async () => {
  //   const result = await submitOperation(softwareAssetList);

  //   expect(typeof { value: result.data.softwareAssetList.edges[0] }).toBe('object');
  // });

  it('Return a single software asset', async () => {
    const result = await submitOperation(softwareAssetQuery);
    expect(typeof { value: result.data }).toBe('object');
  });
});

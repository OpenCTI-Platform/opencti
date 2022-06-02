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

describe('Software Asset Tests', () => {
  let softwareAssetId = '';
  it('Return software asset list', async () => {
    const result = await submitOperation(softwareAssetList);

    expect(typeof { value: result.data.softwareAssetList.edges[0] }).toBe('object');
  });

  it('Create a new software asset', async () => {
    const createSoftwareAsset = `mutation createSoftwareAsset($input: SoftwareAssetAddInput) {
      createSoftwareAsset(input: $input){
        id
    }
  }`;
    const variables = {
      input: {
        name: 'Testing Software Asset',
        asset_type: 'operating_system',
      },
    };
    const result = await submitOperation(createSoftwareAsset, variables);
    softwareAssetId = result.data.createSoftwareAsset.id;

    expect(typeof { value: result.data }).toBe('object');
  });
  it('Return a single software asset', async () => {
    const singleSoftwareAsset = `query softwareAsset($id: ID!) {
      softwareAsset(id:$id){
        id
    }`;
    const variables = { id: softwareAssetId };
    const result = await submitOperation(singleSoftwareAsset, variables);
    expect(typeof { value: result.data }).toBe('object');
  });

  it('Delete the newly created software asset', async () => {
    const deleteSoftwareAsset = `mutation deleteSoftwareAsset($id: ID!) {
      deleteSoftwareAsset(id:$id) }`;

    const variables = { id: softwareAssetId };
    const result = await submitOperation(deleteSoftwareAsset, variables);

    expect(typeof { value: result.data.deleteSoftwareAsset }).toBe('object');
  });
});

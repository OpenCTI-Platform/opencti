import submitOperation from '../../config';

const hardwareAssetList = `query hardwareAssetListQuery {
    hardwareAssetList(first: 1, offset: 0) {
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
describe('Hardware Asset Tests', () => {
  let hardwareAssetId = '';
  it('Return hardware asset list', async () => {
    const result = await submitOperation(hardwareAssetList);

    expect(typeof { value: result.data.hardwareAssetList.edges[0] }).toBe('object');
  });

  it('Create a new hardware asset', async () => {
    const createHardwareAsset = `mutation createHardwareAsset($input: HardwareAssetAddInput) {
      createHardwareAsset(input: $input){
        id
    }
  }`;
    const variables = {
      input: {
        name: 'Testing Hardware Asset',
        asset_type: 'appliance',
      },
    };
    const result = await submitOperation(createHardwareAsset, variables);

    hardwareAssetId = result.data.createHardwareAsset.id;

    expect(typeof { value: result.data }).toBe('object');
  });
  it('Return a single hardware asset', async () => {
    const singleHardwareAsset = `query hardwareAsset($id: ID!) {
      hardwareAsset(id:$id){
        id
      }
    }`;
    const variables = { id: hardwareAssetId };
    const result = await submitOperation(singleHardwareAsset, variables);
    expect(typeof { value: result.data }).toBe('object');
  });

  it('Delete the newly created hardware asset', async () => {
    const deleteHardwareAsset = `mutation deleteHardwareAsset($id: ID!) {
      deleteHardwareAsset(id:$id) }`;

    const variables = { id: hardwareAssetId };
    const result = await submitOperation(deleteHardwareAsset, variables);

    expect(typeof { value: result.data.deleteHardwareAsset }).toBe('object');
  });
});

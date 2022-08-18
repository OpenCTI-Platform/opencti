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
          network_id
        }
      }
    }
  }
`;

describe('Network Asset Tests', () => {
  let networkAssetId = '';
  it('Return network asset list', async () => {
    const result = await submitOperation(networkAssetList);
    expect(typeof { value: result.data.networkAssetList.edges[0] }).toBe('object');
  });

  it('Create a new network asset', async () => {
    const createNetworkAsset = `mutation createNetworkAsset($input: NetworkAssetAddInput) {
      createNetworkAsset(input: $input){
        id
      }
    }`;

    const variables = {
      input: {
        name: 'Testing Network Asset',
        asset_type: 'firewall',
        network_id: 'Test Network Id',
        network_name: 'Test Network Name',
      },
    };
    const result = await submitOperation(createNetworkAsset, variables);
    networkAssetId = result.data.createNetworkAsset.id;

    expect(typeof { value: result.data }).toBe('object');
  });

  it('Return a single network asset', async () => {
    const singleNetworkAsset = `query networkAsset($id: ID!) {
      networkAsset(id:$id){
        id
      }
    }`;
    const variables = { id: networkAssetId };
    const result = await submitOperation(singleNetworkAsset, variables);
    expect(typeof { value: result.data }).toBe('object');
  });

  // it('Delete the newly created network asset', async () => {
  //   const deleteNetworkAsset = `mutation deleteNetworkAsset($id: ID!) {
  //     deleteNetworkAsset(id:$id) }`;

  //   const variables = { id: networkAssetId };
  //   const result = await submitOperation(deleteNetworkAsset, variables);
  //   console.log(result);
  //   expect(typeof { value: result.data.deleteNetworkAsset }).toBe('object');
  // });
});

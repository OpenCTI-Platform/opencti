import submitOperation from '../../config';

const assetListQuery = `
   query {
    assetList(first: 1, offset: 0) {
      pageInfo {
        startCursor
        endCursor
        hasNextPage
        hasPreviousPage
        globalCount
      }
      edges {
        cursor
        node {
          id
          entity_type
          created
          modified
          ... on ComputingDeviceAsset {
            ipv6_address {
              entity_type
              ip_address_value
            }
            uri
          }
        }
      }
    }
  }`;

const assetQuery = `query assetQuery {
  asset(id: "2c14936c-87b1-536e-ac93-b72cb82e996c") {
    id
    entity_type
    created
    modified
  }
}`;

const itAssetListQuery = `query itAssetListQuery {
  itAssetList(first: 1, offset: 0) {
    pageInfo {
      startCursor
      endCursor
    }
    edges {
      node {
        id
        entity_type
        created
        modified
      }
    }
  }
}`;

const itAssetQuery = `query itAssetQuery {
  itAsset(id: "") {
    id
    entity_type
    created
    modified
  }
}`;

const assetLocationListQuery = `query assetLocationListQuery {
  assetLocationList(first: 1, offset: 0) {
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

const assetLocationQuery = `query assetLocationQuery {
  assetLocation(id: "") {
    id
    entity_type
    created
    modified
  }
}`;

describe('Test Common Assets', () => {
  let currentAssetLocationId = '';

  it('Create a new asset location', async () => {
    const createAssetLocation = `mutation createAssetLocation($input: AssetLocationAddInput) {
      createAssetLocation(input: $input){
        id
    }
  }`;
    const variables = {
      input: {
        name: 'Testing Asset Location',
      },
    };
    const result = await submitOperation(createAssetLocation, variables);
    currentAssetLocationId = result.data.createAssetLocation.id;

    expect(typeof { value: result.data }).toBe('object');
  });

  it('Return a single asset location', async () => {
    const result = await submitOperation(assetLocationQuery);
    expect(typeof { value: result.data }).toBe('object');
  });

  it('Return a single asset location', async () => {
    const result = await submitOperation(assetLocationQuery);
    expect(typeof { value: result.data }).toBe('object');
  });

  it('Returns a list of assets', async () => {
    const result = await submitOperation(assetListQuery);

    expect(typeof { value: result.data.assetList.edges[0] }).toBe('object');
  });

  it('Return a single asset', async () => {
    const result = await submitOperation(assetQuery);
    expect(typeof { value: result.data }).toBe('object');
  });

  // ATTEMPT TO CLEAN UP TEST DATA
  it('Delete the newly created asset location', async () => {
    const deleteAssetLocation = `mutation deleteAssetLocation($id: ID!) {
      deleteAssetLocation(id:$id) }`;

    const variables = { id: currentAssetLocationId };
    const result = await submitOperation(deleteAssetLocation, variables);

    expect(typeof { value: result.data.deleteAssetLocation }).toBe('object');
  });
});

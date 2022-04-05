import submitOperation from '../../config';

const computingDeviceAssetList = `query computingDeviceAssetList {
       computingDeviceAssetList(first: 1, offset: 0) {
         edges {
           cursor
           node {
             entity_type
             created
             modified
           }
         }
       }
     }
   `;

const computingDeviceAssetQuery = `query computingDeviceAssetQuery {
    computingDeviceAsset(id: "d114f550-7f30-5331-ab7a-9d56f962230b") {
      id
      entity_type
      created
      modified
    }
  }`;
describe('Successfully Query Computing Device Assets', () => {
  it('Return computing device asset list', async () => {
    const result = await submitOperation(computingDeviceAssetList);

    expect(result.data.computingDeviceAssetList).toBe('object');
  });

  it('Return a singlecomputing device asset', async () => {
    const result = await submitOperation(computingDeviceAssetQuery);
    expect(typeof { value: result.data }).toBe('object');
  });
});

import { ENTITY_TYPE_CONTAINER_REPORT, generateStandardId } from '../../../src/utils/idGenerator';

test('should report ids stable', () => {
  const data = {
    name: 'A demo report for testing purposes',
    published: new Date('2020-03-01T14:02:48.111Z'),
    createdBy: 'identity--7b82b010-b1c0-4dae-981f-7756374a17df', // Will not be used in the key
  };
  for (let i = 0; i < 100; i += 1) {
    const reportStandardId = generateStandardId(ENTITY_TYPE_CONTAINER_REPORT, data);
    expect(reportStandardId).toEqual('report--eb147aa9-f6e7-5b5d-9026-63337bb48a45');
  }
});

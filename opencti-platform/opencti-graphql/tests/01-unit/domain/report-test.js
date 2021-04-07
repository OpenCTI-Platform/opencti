import { generateStandardId, isFieldContributingToStandardId } from '../../../src/schema/identifier';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';
import { ENTITY_HASHED_OBSERVABLE_ARTIFACT } from '../../../src/schema/stixCyberObservable';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../../../src/schema/stixMetaObject';

test('should report ids stable', () => {
  const data = {
    name: 'A demo report for testing purposes',
    published: new Date('2020-03-01T14:02:48.111Z'),
    createdBy: 'identity--7b82b010-b1c0-4dae-981f-7756374a17df', // Will not be used in the key
  };
  const isContributing = isFieldContributingToStandardId({ entity_type: ENTITY_TYPE_CONTAINER_REPORT }, [
    'test',
    'published',
  ]);
  expect(isContributing).toBeTruthy();
  for (let i = 0; i < 100; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const reportStandardId = generateStandardId(ENTITY_TYPE_CONTAINER_REPORT, data);
    expect(reportStandardId).toEqual('report--f3e554eb-60f5-587c-9191-4f25e9ba9f32');
  }
});

test('should observable ids stable', () => {
  const data = { name: 'test', payload_bin: 'test', hashes: { MD5: 'yyyyyyyyyyyyy' } };
  const reportStandardId = generateStandardId(ENTITY_HASHED_OBSERVABLE_ARTIFACT, data);
  expect(reportStandardId).toEqual('artifact--c69d33b1-c44f-57b7-a88c-b0e6225ec16a');
});

test('should external reference ids stable', () => {
  const data = { url: 'http://ssss', source_name: 'http://' };
  const reportStandardId = generateStandardId(ENTITY_TYPE_EXTERNAL_REFERENCE, data);
  expect(reportStandardId).toEqual('external-reference--b92c2140-b505-5236-82af-ae4c42146a23');
});

/* eslint-disable no-underscore-dangle */
import { generateAliasesId, normalizeName } from '../../../src/schema/identifier';
import { relationTypeToInputName } from '../../../src/database/utils';

test('should name correctly normalize', () => {
  let normalize = normalizeName('My data %test     ');
  expect(normalize).toEqual('my data %test');
  normalize = normalizeName('My ♫̟  data  test ');
  expect(normalize).toEqual('my ♫̟  data  test');
  normalize = normalizeName('SnowFlake');
  expect(normalize).toEqual('snowflake');
});

test('should aliases generated with normalization', () => {
  const ids = generateAliasesId(['APT-28', 'SnowFlake']);
  expect(ids).toEqual([
    'aliases--d8ac97ba-19f1-5fa1-8cd6-e956915f4edd',
    'aliases--7312795f-839a-5733-b5f4-c6010ced7a2e',
  ]);
});

test('should relation to input name', () => {
  const name = relationTypeToInputName('object-marking');
  expect(name).toEqual('objectMarking');
});

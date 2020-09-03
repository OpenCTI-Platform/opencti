import { generateAliasesId, normalizeName } from '../../../src/schema/identifier';
import { isValidStixObjectId } from '../../../src/database/stix';

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

test.skip('should stix id correctly detected', () => {
  let isId = isValidStixObjectId('test');
  expect(isId).toBeFalsy();
  isId = isValidStixObjectId('threat-actor--077b66a5-e64f-53df-bb22-03787ea16815');
  expect(isId).toBeTruthy();
  isId = isValidStixObjectId('indicator--10e9a46e-7edb-496b-a167-e27ea3ed0079');
  expect(isId).toBeTruthy();
  isId = isValidStixObjectId('fake--10e9a46e-7edb-496b-a167-e27ea3ed0079');
  expect(isId).toBeFalsy();
  isId = isValidStixObjectId('indicator--1--10e9a46e-7edb-496b-a167-e27ea3ed0079');
  expect(isId).toBeFalsy();
  isId = isValidStixObjectId(null);
  expect(isId).toBeFalsy();
});

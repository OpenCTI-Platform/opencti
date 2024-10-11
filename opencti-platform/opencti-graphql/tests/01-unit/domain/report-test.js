import { expect, it } from 'vitest';
import { generateStandardId, isFieldContributingToStandardId } from '../../../src/schema/identifier';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';
import { ENTITY_HASHED_OBSERVABLE_ARTIFACT } from '../../../src/schema/stixCyberObservable';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../../../src/schema/stixMetaObject';
import { RELATION_BASED_ON, RELATION_USES } from '../../../src/schema/stixCoreRelationship';
import { RELATION_MEMBER_OF } from '../../../src/schema/internalRelationship';
import { RELATION_OBJECT_MARKING } from '../../../src/schema/stixRefRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../src/schema/stixSightingRelationship';
import { UnsupportedError } from '../../../src/config/errors';

it('should report ids stable', () => {
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

it('should observable ids stable', () => {
  const data = { name: 'test', payload_bin: 'test', hashes: { MD5: 'yyyyyyyyyyyyy' } };
  const reportStandardId = generateStandardId(ENTITY_HASHED_OBSERVABLE_ARTIFACT, data);
  expect(reportStandardId).toEqual('artifact--c69d33b1-c44f-57b7-a88c-b0e6225ec16a');
});

it('should external reference ids stable', () => {
  const data = { url: 'http://ssss', source_name: 'http://' };
  const reportStandardId = generateStandardId(ENTITY_TYPE_EXTERNAL_REFERENCE, data);
  expect(reportStandardId).toEqual('external-reference--b92c2140-b505-5236-82af-ae4c42146a23');
});

it('should relation ids be prefixed uuid V4', () => {
  // Internal and meta
  let standardId = generateStandardId(RELATION_MEMBER_OF, {});
  expect(standardId).toMatch(/^internal-relationship--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/);
  standardId = generateStandardId(RELATION_OBJECT_MARKING, {});
  expect(standardId).toMatch(/^relationship-meta--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/);
  // Core and sightings
  standardId = generateStandardId(STIX_SIGHTING_RELATIONSHIP, {
    relationship_type: STIX_SIGHTING_RELATIONSHIP,
    from: { standard_id: 'from_id' },
    to: { standard_id: 'to_id' }
  });
  expect(standardId).toEqual('sighting--161901df-21bb-527a-b96b-354119279fe2');
  standardId = generateStandardId(RELATION_BASED_ON, {
    relationship_type: RELATION_BASED_ON,
    start_time: '2022-11-25T19:00:05.000Z',
    stop_time: '2022-11-26T19:00:05.000Z',
    from: { standard_id: 'from_id' },
    to: { standard_id: 'to_id' }
  });
  expect(standardId).toEqual('relationship--a7778a7d-a743-5193-9912-89f88f9ed0b4');
  standardId = generateStandardId(RELATION_BASED_ON, {
    relationship_type: RELATION_BASED_ON,
    start_time: '2022-11-25T19:00:05.000Z',
    from: { standard_id: 'from_id' },
    to: { standard_id: 'to_id' }
  });
  expect(standardId).toEqual('relationship--c5e1e2ce-14d6-535b-911d-267e92119e01');
  standardId = generateStandardId(RELATION_USES, {
    relationship_type: RELATION_USES,
    start_time: '2020-02-29T22:30:00.000Z',
    stop_time: '2020-02-29T22:30:00.000Z',
    from: { standard_id: 'malware--21c45dbe-54ec-5bb7-b8cd-9f27cc518714' },
    to: { standard_id: 'attack-pattern--fd8179dd-1632-5ec8-8b93-d2ae121e05a4' }
  });
  expect(standardId).toEqual('relationship--67f5f01f-6b15-5154-ae31-019a75fedcff');
});

it('should throw an error on unrecognized object type', () => {
  const data = { foo: 'bar' };
  const fn = () => { generateStandardId('FooBar', data); };
  expect(fn).toThrow(UnsupportedError('FooBar is not supported by the platform'));
});

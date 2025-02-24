import { describe, expect, it } from 'vitest';
import { stixRelationshipsNumber } from '../../../src/domain/stixRelationship';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../src/schema/stixSightingRelationship';
import { ABSTRACT_STIX_RELATIONSHIP } from '../../../src/schema/general';
import { LABEL_FILTER } from '../../../src/utils/filtering/filtering-constants';
import { RELATION_INDICATES, RELATION_RELATED_TO } from '../../../src/schema/stixCoreRelationship';
import { RELATION_OBJECT } from '../../../src/schema/stixRefRelationship';
import { UNTIL_END_STR } from '../../../src/utils/format';

describe('StixRelationship', () => {
  it('should stixRelationship number with object ref relationship', async () => {
    const relationshipsNumberResult = await stixRelationshipsNumber(testContext, ADMIN_USER, {
      dateAttribute: 'created_at',
      endDate: UNTIL_END_STR,
      filters: {
        mode: 'and',
        filters: [{
          key: 'relationship_type',
          values: ['object'],
          operator: 'eq',
          mode: 'or',
        },
        {
          key: 'toTypes',
          values: [ENTITY_TYPE_ATTACK_PATTERN],
          operator: 'eq',
          mode: 'or',
        }],
        filterGroups: [],
      },
    });
    const relationshipsNumber = await relationshipsNumberResult.count;
    expect(relationshipsNumber).toEqual(2); // 2 attack patterns are contained in report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7
  });
  it('should stixRelationship number with object and malware', async () => {
    const relationshipsNumberResult = await stixRelationshipsNumber(testContext, ADMIN_USER, {
      dateAttribute: 'created_at',
      endDate: UNTIL_END_STR,
      filters: {
        mode: 'and',
        filters: [{
          key: 'relationship_type',
          values: [RELATION_OBJECT],
          operator: 'eq',
          mode: 'or',
        },
        {
          key: 'toTypes',
          values: [ENTITY_TYPE_MALWARE],
          operator: 'eq',
          mode: 'or',
        }],
        filterGroups: [],
      },
    });
    const relationshipsNumber = await relationshipsNumberResult.count;
    expect(relationshipsNumber).toEqual(4);
    // 1 malware contained in report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7
    // + 1 in note--573f623c-bf68-4f19-9500-d618f0d00af0
    // + 1 in opinion--fab0d63d-e1be-4771-9c14-043b76f71d4f
    // + 1 in observed-data--7d258c31-9a26-4543-aecb-2abc5ed366be
  });
  it('should stixRelationship number with sighting', async () => {
    // -- stix sighting relationships --
    const relationshipsNumberResult = await stixRelationshipsNumber(testContext, ADMIN_USER, {
      dateAttribute: 'created_at',
      endDate: UNTIL_END_STR,
      filters: {
        mode: 'and',
        filters: [{
          key: 'relationship_type',
          values: [STIX_SIGHTING_RELATIONSHIP],
          operator: 'eq',
          mode: 'or',
        }],
        filterGroups: [],
      },
    });
    const relationshipsNumber = await relationshipsNumberResult.count;
    expect(relationshipsNumber).toEqual(2); // 2 stix-sighting-relationships
  });
  it('should stixRelationship number with indicates and related-to', async () => {
    // -- stix core relationships --
    const relationshipsNumberResult = await stixRelationshipsNumber(testContext, ADMIN_USER, {
      dateAttribute: 'created_at',
      endDate: UNTIL_END_STR,
      filters: {
        mode: 'and',
        filters: [{
          key: 'relationship_type',
          values: [RELATION_RELATED_TO, RELATION_INDICATES],
          operator: 'eq',
          mode: 'or',
        }],
        filterGroups: [],
      },
    });
    const relationshipsNumber = await relationshipsNumberResult.count;
    expect(relationshipsNumber).toEqual(6); // 2 'related-to' relationships + 4 'indicates' relationships
  });
  it('should stixRelationship number with labels', async () => {
    // -- 'label' ref relationship (not taken into account) --
    const relationshipsNumberResult = await stixRelationshipsNumber(testContext, ADMIN_USER, {
      dateAttribute: 'created_at',
      endDate: UNTIL_END_STR,
      filters: {
        mode: 'and',
        filters: [{
          key: 'relationship_type',
          values: [LABEL_FILTER],
          operator: 'eq',
          mode: 'or',
        }],
        filterGroups: [],
      },
    });
    const relationshipsNumber = await relationshipsNumberResult.count;
    expect(relationshipsNumber).toEqual(0); // ref relationships are not taken into account in stixRelationshipsNumber (except the 'object' ref)
  });
  it('should stixRelationship number with all', async () => {
    // -- all relationships --
    const allRelationshipsNumberResult = await stixRelationshipsNumber(testContext, ADMIN_USER, {
      dateAttribute: 'created_at',
      endDate: UNTIL_END_STR,
    });
    const allRelationshipsNumberResult2 = await stixRelationshipsNumber(testContext, ADMIN_USER, {
      dateAttribute: 'created_at',
      endDate: UNTIL_END_STR,
      filters: {
        mode: 'and',
        filters: [{
          key: 'relationship_type',
          values: [ABSTRACT_STIX_RELATIONSHIP],
          operator: 'eq',
          mode: 'or',
        }],
        filterGroups: [],
      },
    });
    const allRelationshipsNumber = await allRelationshipsNumberResult.count;
    const allRelationshipsNumber2 = await allRelationshipsNumberResult2.count;
    expect(allRelationshipsNumber).toEqual(allRelationshipsNumber2); // the relationships taken into account are : stix core, sightings, the 'object' ref
  });
});

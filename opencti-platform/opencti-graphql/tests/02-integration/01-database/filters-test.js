import { describe, expect, it } from 'vitest';
import { ADMIN_USER, buildStandardUser, testContext } from '../../utils/testQuery';
import stixBundle from '../../data/filters/DATA-TEST-FILTERS.json';
import { isEmptyField } from '../../../src/database/utils';
import { ENTITY_TYPE_INTRUSION_SET } from '../../../src/schema/stixDomainObject';
import { isStixMatchFilterGroup_MockableForUnitTests } from '../../../src/utils/filtering/filtering-stix/stix-filtering';

const WHITE_TLP = { standard_id: 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9', internal_id: null };

const applyFilters = async (filters, user = ADMIN_USER) => {
  const filteredObjects = [];
  for (let i = 0; i < stixBundle.objects.length; i += 1) {
    const stix = stixBundle.objects[i];
    const isCurrentlyVisible = await isStixMatchFilterGroup_MockableForUnitTests(testContext, user, stix, filters, new Map());
    if (isCurrentlyVisible) {
      filteredObjects.push(stix);
    }
  }
  return filteredObjects;
};

describe('Filters testing', () => {
  // Filters will not be loaded in cache
  // In this condition we need to put in filtering stix id directly instead of internal ones.

  it('Should marking filters correctly applied for admin user', async () => {
    // With eq on marking
    const filters = {
      mode: 'and',
      filters: [{
        key: ['objectMarking'],
        values: ['marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27'],
        operator: 'eq',
        mode: 'or',
      }],
      filterGroups: [],
    };
    const filteredObjects = await applyFilters(filters);
    expect(filteredObjects.length).toBe(17);
    for (let objectIndex = 0; objectIndex < filteredObjects.length; objectIndex += 1) {
      const filteredObject = filteredObjects[objectIndex];
      expect(filteredObject.object_marking_refs.includes('marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27')).toBe(true);
    }
    // With _not_eq
    const filtersNot = {
      mode: 'and',
      filters: [{
        key: ['objectMarking'],
        values: ['marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27'],
        operator: 'not_eq',
        mode: 'or',
      }],
      filterGroups: [],
    };
    const filteredObjectsNot = await applyFilters(filtersNot);
    expect(stixBundle.objects.length - filteredObjects.length).toBe(filteredObjectsNot.length);
  });

  it('Should marking filters correctly applied for standard user', async () => {
    const WHITE_USER = buildStandardUser([WHITE_TLP]);
    // With eq on marking
    const filters = {
      mode: 'and',
      filters: [{
        key: ['createdBy'],
        values: ['identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5'],
        operator: 'eq',
        mode: 'or',
      }],
      filterGroups: [],
    };
    const filteredObjectsWhite = await applyFilters(filters, WHITE_USER);
    expect(filteredObjectsWhite.length).toBe(0);
    const filteredObjectAdmin = await applyFilters(filters);
    expect(filteredObjectAdmin.length).toBe(3);
  });

  // Should type filters correctly applied => Not possible without stix with extensions
  it('Should entity filters correctly applied for standard user', async () => {
    const WHITE_USER = buildStandardUser([WHITE_TLP]);
    // With eq on marking
    const filters = {
      mode: 'and',
      filters: [{
        key: ['entity_type'],
        values: [ENTITY_TYPE_INTRUSION_SET],
        operator: 'eq',
        mode: 'or',
      }],
      filterGroups: [],
    };
    const filteredObjectsWhite = await applyFilters(filters, WHITE_USER);
    expect(filteredObjectsWhite.length).toBe(0);
    const filteredObjectAdmin = await applyFilters(filters);
    expect(filteredObjectAdmin.length).toBe(1);
  });

  // indicator_types not available in the data set

  // workflow_filter

  it('Should createdBy filters correctly applied', async () => {
    // With eq on marking
    const filters = {
      mode: 'and',
      filters: [{
        key: ['createdBy'],
        values: ['identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5'],
        operator: 'eq',
        mode: 'or',
      }],
      filterGroups: [],
    };
    const filteredObjects = await applyFilters(filters);
    expect(filteredObjects.length).toBe(3);
    // With _not_eq
    const filtersNot = {
      mode: 'and',
      filters: [{
        key: ['createdBy'],
        values: ['identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5'],
        operator: 'not_eq',
        mode: 'or',
      }],
      filterGroups: [],
    };
    const filteredObjectsNot = await applyFilters(filtersNot);
    expect(stixBundle.objects.length - filteredObjects.length).toBe(filteredObjectsNot.length);
  });

  // assignee_filter

  it('Should labels filters correctly applied', async () => {
    // With eq on marking
    const filters = {
      mode: 'and',
      filters: [{
        key: ['objectLabel'],
        values: ['attack-pattern'],
        operator: 'eq',
        mode: 'or',
      }],
      filterGroups: [],
    };
    const filteredObjects = await applyFilters(filters);
    expect(filteredObjects.length).toBe(2);
    // With _not_eq
    const filtersNot = {
      mode: 'and',
      filters: [{
        key: ['objectLabel'],
        values: ['attack-pattern'],
        operator: 'not_eq',
        mode: 'or',
      }],
      filterGroups: [],
    };
    const filteredObjectsNot = await applyFilters(filtersNot);
    expect(stixBundle.objects.length - filteredObjects.length).toBe(filteredObjectsNot.length);
  });

  // revoked

  it('Should confidence filters correctly applied', async () => {
    // With gte on marking
    const filters = {
      mode: 'and',
      filters: [{
        key: ['confidence'],
        values: ['30'],
        operator: 'gte',
        mode: 'or',
      }],
      filterGroups: [],
    };
    const filteredObjects = await applyFilters(filters);
    expect(filteredObjects.length).toBe(9);
    // With lt
    const filtersNot = {
      mode: 'and',
      filters: [{
        key: ['confidence'],
        values: ['30'],
        operator: 'lt',
        mode: 'or',
      }],
      filterGroups: [],
    };
    const filteredObjectsNot = await applyFilters(filtersNot);
    expect(filteredObjectsNot.length).toBe(8);
    // With nothing
    const noConfidenceSize = stixBundle.objects.filter((stix) => isEmptyField(stix.confidence)).length;
    const remainingSize = stixBundle.objects.length - filteredObjects.length - filteredObjectsNot.length;
    expect(remainingSize).toBe(noConfidenceSize);
  });

  it('Should pattern_type filters correctly applied', async () => {
    // With eq on marking
    const filters = {
      mode: 'and',
      filters: [{
        key: ['pattern_type'],
        values: ['stix'],
        operator: 'eq',
        mode: 'or',
      }],
      filterGroups: [],
    };
    const filteredObjects = await applyFilters(filters);
    expect(filteredObjects.length).toBe(3);
  });

  it('Should objects filters correctly applied', async () => {
    // With eq on marking
    const filters = {
      mode: 'and',
      filters: [{
        key: ['objects'],
        values: ['note--573f623c-bf68-4f19-9500-d618f0d00af0'],
        operator: 'eq',
        mode: 'or',
      }],
      filterGroups: [],
    };
    const filteredObjects = await applyFilters(filters);
    expect(filteredObjects.length).toBe(1);
    // With _not_eq
    const filtersNot = {
      mode: 'and',
      filters: [{
        key: ['objects'],
        values: ['note--573f623c-bf68-4f19-9500-d618f0d00af0'],
        operator: 'not_eq',
        mode: 'or',
      }],
      filterGroups: [],
    };
    const filteredObjectsNot = await applyFilters(filtersNot);
    expect(stixBundle.objects.length - filteredObjects.length).toBe(filteredObjectsNot.length);
  });

  it('Should from filters correctly applied', async () => {
    // With eq on marking
    const filters = {
      mode: 'and',
      filters: [{
        key: ['fromId'],
        values: ['indicator--a2f7504a-ea0d-48ed-a18d-cbf352fae6cf'],
        operator: 'eq',
        mode: 'or',
      }],
      filterGroups: [],
    };
    const filteredObjects = await applyFilters(filters);
    expect(filteredObjects.length).toBe(3); // 2 source_ref, 1 sighting_of_ref
  });

  it('Should to filters correctly applied', async () => {
    // With eq on marking
    const filters = {
      mode: 'and',
      filters: [{
        key: ['toId'],
        values: ['location--6bf1f67a-6a55-4e4d-b237-6cdda97baef2'],
        operator: 'eq',
        mode: 'or',
      }],
      filterGroups: [],
    };
    const filteredObjects = await applyFilters(filters);
    expect(filteredObjects.length).toBe(1);
  });

  // severity
  it('Should severity filters correctly applied', async () => {
    const filters = {
      mode: 'and',
      filters: [{
        key: ['severity'],
        values: ['low'],
        operator: 'eq',
        mode: 'or',
      }],
      filterGroups: [],
    };
    const filteredObjects = await applyFilters(filters);
    expect(filteredObjects.length).toBe(0); // no severity in the data

    const filtersNo = {
      mode: 'and',
      filters: [{ key: ['severity'], values: [], operator: 'nil', mode: 'or' }],
      filterGroups: [],
    };
    const filteredObjectsNo = await applyFilters(filtersNo);
    expect(filteredObjectsNo.length).toBe(64);
  });

  // priority
  it('Should priority filters correctly applied', async () => {
    const filters = {
      mode: 'and',
      filters: [{
        key: ['priority'],
        values: ['p2'],
        operator: 'eq',
        mode: 'or',
      }],
      filterGroups: [],
    };
    const filteredObjects = await applyFilters(filters);
    expect(filteredObjects.length).toBe(0); // no priority in the data

    const filtersNo = {
      mode: 'and',
      filters: [{ key: ['priority'], values: [], operator: 'nil', mode: 'or' }],
      filterGroups: [],
    };
    const filteredObjectsNo = await applyFilters(filtersNo);
    expect(filteredObjectsNo.length).toBe(64);
  });
});

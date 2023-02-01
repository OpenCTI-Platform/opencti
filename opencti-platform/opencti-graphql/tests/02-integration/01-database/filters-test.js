import { describe, expect, it } from 'vitest';
import { isStixMatchFilters } from '../../../src/utils/filtering';
import { ADMIN_USER, buildStandardUser, testContext } from '../../utils/testQuery';
import data from '../../data/DATA-TEST-STIX2_v2.json';
import { isEmptyField } from '../../../src/database/utils';
import { ENTITY_TYPE_INTRUSION_SET } from '../../../src/schema/stixDomainObject';

const WHITE_TLP = { standard_id: 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9', internal_id: null };

const applyFilters = async (filters, user = ADMIN_USER) => {
  const filteredObjects = [];
  for (let i = 0; i < data.objects.length; i += 1) {
    const stix = data.objects[i];
    const isCurrentlyVisible = await isStixMatchFilters(testContext, user, stix, filters);
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
    const filters = { markedBy: [{ id: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27' }] };
    const filteredObjects = await applyFilters(filters);
    expect(filteredObjects.length).toBe(13);
    for (let objectIndex = 0; objectIndex < filteredObjects.length; objectIndex += 1) {
      const filteredObject = filteredObjects[objectIndex];
      expect(filteredObject.object_marking_refs.includes('marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27')).toBe(true);
    }
    // With _not_eq
    const filtersNot = { markedBy_not_eq: [{ id: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27' }] };
    const filteredObjectsNot = await applyFilters(filtersNot);
    expect(data.objects.length - filteredObjects.length).toBe(filteredObjectsNot.length);
  });

  it('Should marking filters correctly applied for standard user', async () => {
    const WHITE_USER = buildStandardUser([WHITE_TLP]);
    // With eq on marking
    const filters = { createdBy: [{ id: 'identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5' }] };
    const filteredObjectsWhite = await applyFilters(filters, WHITE_USER);
    expect(filteredObjectsWhite.length).toBe(0);
    const filteredObjectAdmin = await applyFilters(filters);
    expect(filteredObjectAdmin.length).toBe(3);
  });

  // Should type filters correctly applied => Not possible without stix with extensions
  it('Should entity filters correctly applied for standard user', async () => {
    const WHITE_USER = buildStandardUser([WHITE_TLP]);
    // With eq on marking
    const filters = { entity_type: [{ id: ENTITY_TYPE_INTRUSION_SET }] };
    const filteredObjectsWhite = await applyFilters(filters, WHITE_USER);
    expect(filteredObjectsWhite.length).toBe(0);
    const filteredObjectAdmin = await applyFilters(filters);
    expect(filteredObjectAdmin.length).toBe(1);
  });

  // indicator_types not available in the data set

  // workflow_filter

  it('Should createdBy filters correctly applied', async () => {
    // With eq on marking
    const filters = { createdBy: [{ id: 'identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5' }] };
    const filteredObjects = await applyFilters(filters);
    expect(filteredObjects.length).toBe(3);
    // With _not_eq
    const filtersNot = { createdBy_not_eq: [{ id: 'identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5' }] };
    const filteredObjectsNot = await applyFilters(filtersNot);
    expect(data.objects.length - filteredObjects.length).toBe(filteredObjectsNot.length);
  });

  // assignee_filter

  it('Should labels filters correctly applied', async () => {
    // With eq on marking
    const filters = { labelledBy: [{ id: 'attack-pattern', value: 'attack-pattern' }] };
    const filteredObjects = await applyFilters(filters);
    expect(filteredObjects.length).toBe(2);
    // With _not_eq
    const filtersNot = { labelledBy_not_eq: [{ id: 'attack-pattern', value: 'attack-pattern' }] };
    const filteredObjectsNot = await applyFilters(filtersNot);
    expect(data.objects.length - filteredObjects.length).toBe(filteredObjectsNot.length);
  });

  // revoked

  it('Should confidence filters correctly applied', async () => {
    // With gte on marking
    const filters = { confidence_gte: [{ id: 30 }] };
    const filteredObjects = await applyFilters(filters);
    expect(filteredObjects.length).toBe(8);
    // With lt
    const filtersNot = { confidence_lt: [{ id: 30 }] };
    const filteredObjectsNot = await applyFilters(filtersNot);
    expect(filteredObjectsNot.length).toBe(8);
    // With nothing
    const noConfidenceSize = data.objects.filter((stix) => isEmptyField(stix.confidence)).length;
    const remainingSize = data.objects.length - filteredObjects.length - filteredObjectsNot.length;
    expect(remainingSize).toBe(noConfidenceSize);
  });

  it('Should pattern_type filters correctly applied', async () => {
    // With eq on marking
    const filters = { pattern_type: [{ id: 'stix' }] };
    const filteredObjects = await applyFilters(filters);
    expect(filteredObjects.length).toBe(3);
  });

  it('Should objects filters correctly applied', async () => {
    // With eq on marking
    const filters = { objectContains: [{ id: 'note--573f623c-bf68-4f19-9500-d618f0d00af0' }] };
    const filteredObjects = await applyFilters(filters);
    expect(filteredObjects.length).toBe(1);
    // With _not_eq
    const filtersNot = { objectContains_not_eq: [{ id: 'note--573f623c-bf68-4f19-9500-d618f0d00af0' }] };
    const filteredObjectsNot = await applyFilters(filtersNot);
    expect(data.objects.length - filteredObjects.length).toBe(filteredObjectsNot.length);
  });

  it('Should from filters correctly applied', async () => {
    // With eq on marking
    const filters = { fromId: [{ id: 'indicator--a2f7504a-ea0d-48ed-a18d-cbf352fae6cf' }] };
    const filteredObjects = await applyFilters(filters);
    expect(filteredObjects.length).toBe(3); // 2 source_ref, 1 sighting_of_ref
  });

  it('Should to filters correctly applied', async () => {
    // With eq on marking
    const filters = { toId: [{ id: 'location--6bf1f67a-6a55-4e4d-b237-6cdda97baef2' }] };
    const filteredObjects = await applyFilters(filters);
    expect(filteredObjects.length).toBe(1);
  });
});

import { afterAll, describe, expect, it } from 'vitest';
import { addObservedData } from '../../../src/domain/observedData';
import { stixDomainObjectDelete } from '../../../src/domain/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_OBSERVED_DATA } from '../../../src/schema/stixDomainObject';
import { isEmptyField } from '../../../src/database/utils';
import { ADMIN_USER, testContext } from '../../utils/testQuery';

// Entities of the injected dataset (DATA-TEST-STIX2_v2.json). The standard id of an observed data is derived from its
// objects, so these must differ from the objects of the dataset observed data (a single malware) to create new elements.
const ATTACK_PATTERN_STIX_ID = 'attack-pattern--489a7797-01c3-4706-8cd1-ec56a9db3adc';
const INTRUSION_SET_STIX_ID = 'intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7';

describe('Observed data counters (number_seen, max_distinct_count)', () => {
  // Every created observed data is deleted at the end (see tests/utils/syncCountHelper.ts for the stream counters)
  const createdIds: string[] = [];
  afterAll(async () => {
    const uniqueIds = [...new Set(createdIds)];
    for (let i = 0; i < uniqueIds.length; i += 1) {
      await stixDomainObjectDelete(testContext, ADMIN_USER, uniqueIds[i], ENTITY_TYPE_CONTAINER_OBSERVED_DATA);
    }
  });

  const baseInput = {
    first_observed: '2026-09-01T00:00:00.000Z',
    last_observed: '2026-09-10T00:00:00.000Z',
    number_observed: 100,
  };

  it('should default number_seen to 1 at creation and consolidate the counters on upsert', async () => {
    const input = { ...baseInput, objects: [ATTACK_PATTERN_STIX_ID] };
    const created = await addObservedData(testContext, ADMIN_USER, input);
    createdIds.push(created.id);
    expect(created.number_seen).toEqual(1);
    expect(isEmptyField(created.max_distinct_count)).toBeTruthy();
    // Same observed data ingested again with an unchanged window: seen once more, total unchanged, max initialized
    const upserted = await addObservedData(testContext, ADMIN_USER, { ...input, max_distinct_count: 10 });
    expect(upserted.id).toEqual(created.id);
    expect(upserted.number_seen).toEqual(2);
    expect(upserted.number_observed).toEqual(100);
    expect(upserted.max_distinct_count).toEqual(10);
    // A provided increment is summed and a lower distinct count keeps the existing maximum
    const upsertedAgain = await addObservedData(testContext, ADMIN_USER, { ...input, number_seen: 5, max_distinct_count: 4 });
    expect(upsertedAgain.id).toEqual(created.id);
    expect(upsertedAgain.number_seen).toEqual(7);
    expect(upsertedAgain.max_distinct_count).toEqual(10);
  });

  it('should keep the counters provided at creation', async () => {
    const created = await addObservedData(testContext, ADMIN_USER, { ...baseInput, objects: [INTRUSION_SET_STIX_ID], number_seen: 3, max_distinct_count: 2 });
    createdIds.push(created.id);
    expect(created.number_seen).toEqual(3);
    expect(created.max_distinct_count).toEqual(2);
  });

  it('should reject negative counters', async () => {
    await expect(addObservedData(testContext, ADMIN_USER, { ...baseInput, objects: [INTRUSION_SET_STIX_ID], number_seen: -1 }))
      .rejects.toThrow('The counter should be a non-negative integer');
    await expect(addObservedData(testContext, ADMIN_USER, { ...baseInput, objects: [INTRUSION_SET_STIX_ID], max_distinct_count: -1 }))
      .rejects.toThrow('The counter should be a non-negative integer');
  });
});

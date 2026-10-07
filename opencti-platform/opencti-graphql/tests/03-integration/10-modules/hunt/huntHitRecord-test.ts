import { afterAll, describe, expect, it } from 'vitest';
import { v4 as uuid } from 'uuid';
import { testContext } from '../../../utils/testQuery';
import { elRawDeleteByQuery } from '../../../../src/database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../../../../src/database/utils';
import { findHuntHitRecords, huntHitRecordId, purgeExpiredHuntHitRecords, recordHuntHits } from '../../../../src/modules/hunt/huntHitRecord/huntHitRecord-domain';

// A hunt and a platform of their own, so the records of this test are never those of another test
const huntId = uuid();
const securityPlatformId = uuid();
const HIT = 'hit-late-evidence';
const LATEST = '2026-01-10T12:00:00.000Z';
const OLDER = '2026-01-05T08:30:00.000Z';
const LATER = '2026-01-12T07:15:00.000Z';

const lastSeen = async () => {
  const record = (await findHuntHitRecords(testContext, huntId, securityPlatformId, [HIT])).get(HIT);
  return { timesSeen: record?.times_seen, lastSeen: record?.last_seen ? new Date(record.last_seen).toISOString() : undefined };
};

describe('Hunt hit records', () => {
  afterAll(async () => {
    await elRawDeleteByQuery({
      index: READ_INDEX_INTERNAL_OBJECTS,
      refresh: true,
      wait_for_completion: true,
      body: { query: { ids: { values: [huntHitRecordId(huntId, securityPlatformId, HIT).internalId] } } },
    });
  });

  it('should keep the latest sighting of a hit when the late evidence of another run is older', async () => {
    expect(await recordHuntHits(testContext, { huntId, securityPlatformId, runId: uuid(), keys: [HIT], seenAt: LATEST }))
      .toEqual({ newCount: 1, recurringCount: 0 });
    expect(await recordHuntHits(testContext, { huntId, securityPlatformId, runId: uuid(), keys: [HIT], seenAt: OLDER }))
      .toEqual({ newCount: 0, recurringCount: 1 });
    expect(await lastSeen()).toEqual({ timesSeen: 2, lastSeen: LATEST });
  });

  it('should keep a hit sighted recently through the retention of the older hits', async () => {
    await purgeExpiredHuntHitRecords('2026-01-08T00:00:00.000Z');
    expect(await lastSeen()).toEqual({ timesSeen: 2, lastSeen: LATEST });
  });

  it('should move the latest sighting forward when a later run finds the hit again', async () => {
    await recordHuntHits(testContext, { huntId, securityPlatformId, runId: uuid(), keys: [HIT], seenAt: LATER });
    expect(await lastSeen()).toEqual({ timesSeen: 3, lastSeen: LATER });
  });

  it('should count a run processed again after a later run once, keeping the later run as the last one', async () => {
    const interrupted = uuid();
    const later = uuid();
    await recordHuntHits(testContext, { huntId, securityPlatformId, runId: interrupted, keys: [HIT], seenAt: LATER });
    await recordHuntHits(testContext, { huntId, securityPlatformId, runId: later, keys: [HIT], seenAt: LATER });
    expect(await recordHuntHits(testContext, { huntId, securityPlatformId, runId: interrupted, keys: [HIT], seenAt: LATER }))
      .toEqual({ newCount: 0, recurringCount: 1 });
    const record = (await findHuntHitRecords(testContext, huntId, securityPlatformId, [HIT])).get(HIT);
    expect(record?.times_seen).toEqual(5);
    expect(record?.last_run_id).toEqual(later);
    expect(record?.counted_run_ids?.slice(-2)).toEqual([interrupted, later]);
  });

  it('should leave a known hit as it is for late evidence of a run the records may have forgotten', async () => {
    expect(await recordHuntHits(testContext, { huntId, securityPlatformId, runId: uuid(), keys: [HIT], seenAt: LATER, keepKnown: true }))
      .toEqual({ newCount: 0, recurringCount: 1 });
    expect((await lastSeen()).timesSeen).toEqual(5);
  });
});

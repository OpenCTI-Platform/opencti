import { afterAll, describe, expect, it } from 'vitest';
import { v4 as uuid } from 'uuid';
import { ADMIN_USER, getAuthUser, testContext, USER_EDITOR } from '../../../utils/testQuery';
import { elCount, elRawDeleteByQuery } from '../../../../src/database/engine';
import { internalLoadById } from '../../../../src/database/middleware-loader';
import { READ_INDEX_INTERNAL_OBJECTS } from '../../../../src/database/utils';
import { FilterMode } from '../../../../src/generated/graphql';
import { MARKING_TLP_RED } from '../../../../src/schema/identifier';
import type { BasicStoreEntity } from '../../../../src/types/store';
import type { AuthUser } from '../../../../src/types/user';
import { findHuntHitRecords, huntHitRecordId, purgeExpiredHuntHitRecords, recordHuntHits } from '../../../../src/modules/hunt/huntHitRecord/huntHitRecord-domain';
import { ENTITY_TYPE_HUNT_HIT_RECORD } from '../../../../src/modules/hunt/huntHitRecord/huntHitRecord-types';
import { stixCoreObjectsNumber } from '../../../../src/domain/stixCoreObject';

// A hunt and a platform of their own, so the records of this test are never those of another test
const huntId = uuid();
const securityPlatformId = uuid();
const HIT = 'hit-late-evidence';
const MARKED_HIT = 'hit-restricted-run';
const CONTEXT_HIT = 'hit-hunt-context';
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
      body: { query: { ids: { values: [HIT, MARKED_HIT, CONTEXT_HIT].map((key) => huntHitRecordId(huntId, securityPlatformId, key).internalId) } } },
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
    await purgeExpiredHuntHitRecords('2026-01-08T00:00:00.000Z', 10000);
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

  it('should carry the markings of every run that found a hit, hiding it from a user who cannot read one of them', async () => {
    const red = await internalLoadById<BasicStoreEntity>(testContext, ADMIN_USER, MARKING_TLP_RED);
    const editor = await getAuthUser(USER_EDITOR.id);
    const readable = (user: AuthUser) => elCount(testContext, user, READ_INDEX_INTERNAL_OBJECTS, {
      types: [ENTITY_TYPE_HUNT_HIT_RECORD],
      filters: { mode: FilterMode.And, filters: [{ key: ['hunt_id'], values: [huntId] }, { key: ['hit_key'], values: [MARKED_HIT] }], filterGroups: [] },
    });
    await recordHuntHits(testContext, { huntId, securityPlatformId, runId: uuid(), keys: [MARKED_HIT], seenAt: LATEST, objectMarking: [] });
    expect(await readable(editor)).toEqual(1);
    // A run restricted to TLP:RED finds the hit again: the editor, who cannot read TLP:RED, no longer reads its record
    await recordHuntHits(testContext, { huntId, securityPlatformId, runId: uuid(), keys: [MARKED_HIT], seenAt: LATER, objectMarking: [red.internal_id] });
    expect(await readable(editor)).toEqual(0);
    expect(await readable(ADMIN_USER)).toEqual(1);
    // A later run without the marking does not lift it
    await recordHuntHits(testContext, { huntId, securityPlatformId, runId: uuid(), keys: [MARKED_HIT], seenAt: LATER, objectMarking: [] });
    expect(await readable(editor)).toEqual(0);
  });

  it('should be counted by the dashboard widgets on the type, origin and techniques of their hunt', async () => {
    const techniqueId = uuid();
    const huntContext = { hunt_type: 'indicators', hunt_source_kind: 'agent', hunt_technique_ids: [techniqueId] };
    await recordHuntHits(testContext, { huntId, securityPlatformId, runId: uuid(), keys: [CONTEXT_HIT], seenAt: LATEST, huntContext });
    const count = (filters: { key: string[]; values: string[] }[]) => stixCoreObjectsNumber(testContext, ADMIN_USER, {
      filters: {
        mode: FilterMode.And,
        filters: [{ key: ['entity_type'], values: [ENTITY_TYPE_HUNT_HIT_RECORD] }, { key: ['hunt_id'], values: [huntId] }, ...filters],
        filterGroups: [],
      },
    }).count;
    expect(await count([{ key: ['hunt_type'], values: ['indicators'] }, { key: ['hunt_source_kind'], values: ['agent'] }, { key: ['hunt_technique_ids'], values: [techniqueId] }]))
      .toEqual(1);
    expect(await count([{ key: ['hunt_type'], values: ['telemetry'] }])).toEqual(0);
    // The hit found again by a run of another context keeps the context it was first found with
    await recordHuntHits(testContext, { huntId, securityPlatformId, runId: uuid(), keys: [CONTEXT_HIT], seenAt: LATER, huntContext: { ...huntContext, hunt_source_kind: 'analyst' } });
    expect(await count([{ key: ['hunt_source_kind'], values: ['agent'] }, { key: ['hit_key'], values: [CONTEXT_HIT] }])).toEqual(1);
  });
});

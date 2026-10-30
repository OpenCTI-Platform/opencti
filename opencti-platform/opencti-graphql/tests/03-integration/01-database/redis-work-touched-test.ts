import { describe, expect, it } from 'vitest';
import {
  getClientBase,
  redisAddWorkTouchedElements,
  redisDeleteWorks,
  redisGetWork,
  redisGetWorkTouchedElements,
  redisGetWorkTrackingInfo,
  redisInitializeWork,
  WORK_TOUCHED_TTL,
} from '../../../src/database/redis';

/**
 * Build a unique work id so that each test uses its own Redis keys.
 */
const newWorkId = () => `work_redis-touched-test_${Date.now()}_${Math.floor(Math.random() * 100000)}`;

describe('Redis work touched elements', () => {
  it('should store the event type, the investigation id and the enriched entity id with the work', async () => {
    const workId = newWorkId();
    await redisInitializeWork(workId, false, 'INTERNAL_ENRICHMENT', 'investigation-1', 'enriched-1');
    expect(await redisGetWorkTrackingInfo(workId)).toEqual({ eventType: 'INTERNAL_ENRICHMENT', investigationId: 'investigation-1', enrichedEntityId: 'enriched-1' });
    expect((await redisGetWork(workId)).is_initialized).toEqual('true');
    await redisDeleteWorks([workId]);
  });

  it('should return null tracking info for a work initialized without them', async () => {
    const workId = newWorkId();
    await redisInitializeWork(workId, false);
    expect(await redisGetWorkTrackingInfo(workId)).toEqual({ eventType: null, investigationId: null, enrichedEntityId: null });
    await redisDeleteWorks([workId]);
  });

  it('should collect each touched id once', async () => {
    const workId = newWorkId();
    await redisAddWorkTouchedElements(workId, ['a', 'a']);
    await redisAddWorkTouchedElements(workId, ['b', 'a']);
    const touched = await redisGetWorkTouchedElements(workId);
    expect(touched.touched_ids.sort()).toEqual(['a', 'b']);
    await redisDeleteWorks([workId]);
  });

  it('should set a TTL on the touched key', async () => {
    const workId = newWorkId();
    await redisAddWorkTouchedElements(workId, ['a']);
    const ttl = await getClientBase().ttl(`work_touched:${workId}`);
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(WORK_TOUCHED_TTL);
    await redisDeleteWorks([workId]);
  });

  it('should refuse ids beyond the cap', async () => {
    const workId = newWorkId();
    expect(await redisAddWorkTouchedElements(workId, ['a'], 2)).toBe(true);
    expect(await redisAddWorkTouchedElements(workId, ['b', 'c'], 2)).toBe(false);
    const touched = await redisGetWorkTouchedElements(workId);
    expect(touched.touched_ids.sort()).toEqual(['a', 'b']);
    await redisDeleteWorks([workId]);
  });

  it('should not count an id already recorded as refused by the cap', async () => {
    const workId = newWorkId();
    await redisAddWorkTouchedElements(workId, ['a', 'b'], 2);
    expect(await redisAddWorkTouchedElements(workId, ['a'], 2)).toBe(true);
    await redisDeleteWorks([workId]);
  });

  it('should delete the touched set with the work', async () => {
    const workId = newWorkId();
    await redisInitializeWork(workId, false, 'INTERNAL_ENRICHMENT');
    await redisAddWorkTouchedElements(workId, ['a']);
    await redisDeleteWorks([workId]);
    expect(await redisGetWorkTouchedElements(workId)).toEqual({ touched_ids: [] });
  });
});

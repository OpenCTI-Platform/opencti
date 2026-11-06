import { describe, expect, it } from 'vitest';
import {
  getClientBase,
  redisAddWorkTouchedElements,
  redisDeleteWorks,
  redisGetWork,
  redisGetWorkTouchedElements,
  redisInitializeWork,
  WORK_TOUCHED_TTL,
} from '../../../src/database/redis';

/**
 * Build a unique work id so that each test uses its own Redis keys.
 */
const newWorkId = () => `work_redis-touched-test_${Date.now()}_${Math.floor(Math.random() * 100000)}`;

describe('Redis work touched elements', () => {
  // Read by createGraphqlContext to tell whether and how the touched elements of the work are tracked
  it('should store the event type, the investigation id and the enriched entity id with the work', async () => {
    const workId = newWorkId();
    await redisInitializeWork(workId, false, undefined, 'INTERNAL_ENRICHMENT', 'investigation-1', 'enriched-1');
    expect(await redisGetWork(workId)).toEqual(expect.objectContaining({
      is_initialized: 'true',
      event_type: 'INTERNAL_ENRICHMENT',
      investigation_id: 'investigation-1',
      enriched_entity_id: 'enriched-1',
    }));
    await redisDeleteWorks([workId]);
  });

  it('should not store the tracking fields of a work initialized without them', async () => {
    const workId = newWorkId();
    await redisInitializeWork(workId, false);
    const work = await redisGetWork(workId);
    expect(work.is_initialized).toEqual('true');
    expect(work).not.toHaveProperty('event_type');
    expect(work).not.toHaveProperty('investigation_id');
    expect(work).not.toHaveProperty('enriched_entity_id');
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
    await redisInitializeWork(workId, false, undefined, 'INTERNAL_ENRICHMENT');
    await redisAddWorkTouchedElements(workId, ['a']);
    await redisDeleteWorks([workId]);
    expect(await redisGetWorkTouchedElements(workId)).toEqual({ touched_ids: [] });
  });
});

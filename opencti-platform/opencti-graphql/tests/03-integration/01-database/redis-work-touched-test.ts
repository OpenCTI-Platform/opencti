import { describe, expect, it } from 'vitest';
import {
  getClientBase,
  redisAddWorkTouchedElement,
  redisDeleteWorks,
  redisGetWork,
  redisGetWorkEventType,
  redisGetWorkTouchedElements,
  redisInitializeWork,
  WORK_TOUCHED_TTL,
} from '../../../src/database/redis';

/**
 * Build a unique work id so that each test uses its own Redis keys.
 */
const newWorkId = () => `work_redis-touched-test_${Date.now()}_${Math.floor(Math.random() * 100000)}`;

describe('Redis work touched elements', () => {
  it('should store the event type with the work', async () => {
    const workId = newWorkId();
    await redisInitializeWork(workId, false, 'INTERNAL_ENRICHMENT');
    expect(await redisGetWorkEventType(workId)).toEqual('INTERNAL_ENRICHMENT');
    expect((await redisGetWork(workId)).is_initialized).toEqual('true');
    await redisDeleteWorks([workId]);
  });

  it('should return null event type for a work initialized without one', async () => {
    const workId = newWorkId();
    await redisInitializeWork(workId, false);
    expect(await redisGetWorkEventType(workId)).toBeNull();
    await redisDeleteWorks([workId]);
  });

  it('should collect each touched id once', async () => {
    const workId = newWorkId();
    await redisAddWorkTouchedElement(workId, 'a');
    await redisAddWorkTouchedElement(workId, 'a');
    await redisAddWorkTouchedElement(workId, 'b');
    const touched = await redisGetWorkTouchedElements(workId);
    expect(touched.touched_ids.sort()).toEqual(['a', 'b']);
    await redisDeleteWorks([workId]);
  });

  it('should set a TTL on the touched key', async () => {
    const workId = newWorkId();
    await redisAddWorkTouchedElement(workId, 'a');
    const ttl = await getClientBase().ttl(`work_touched:${workId}`);
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(WORK_TOUCHED_TTL);
    await redisDeleteWorks([workId]);
  });

  it('should refuse ids beyond the cap', async () => {
    const workId = newWorkId();
    expect(await redisAddWorkTouchedElement(workId, 'a', 2)).toBe(true);
    expect(await redisAddWorkTouchedElement(workId, 'b', 2)).toBe(true);
    expect(await redisAddWorkTouchedElement(workId, 'c', 2)).toBe(false);
    const touched = await redisGetWorkTouchedElements(workId);
    expect(touched.touched_ids.sort()).toEqual(['a', 'b']);
    await redisDeleteWorks([workId]);
  });

  it('should delete the touched set with the work', async () => {
    const workId = newWorkId();
    await redisInitializeWork(workId, false, 'INTERNAL_ENRICHMENT');
    await redisAddWorkTouchedElement(workId, 'a');
    await redisDeleteWorks([workId]);
    expect(await redisGetWorkTouchedElements(workId)).toEqual({ touched_ids: [] });
  });
});

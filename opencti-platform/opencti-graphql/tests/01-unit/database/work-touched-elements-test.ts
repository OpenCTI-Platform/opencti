import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as redis from '../../../src/database/redis';
import { clearCompletedWorkTouchedElements, resetWorkEventTypeCache, trackWorkTouchedElement } from '../../../src/database/work-touched-elements';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';
import { testContext } from '../../utils/testQuery';
import { logApp } from '../../../src/config/conf';

vi.mock('../../../src/database/redis', async (importOriginal) => {
  const actual: object = await importOriginal();
  return { ...actual, redisGetWorkEventType: vi.fn(), redisAddWorkTouchedElement: vi.fn(), redisDeleteWorkTouchedElements: vi.fn() };
});

/** Build a minimal stream event carrying the given internal id. */
const event = (type: string, id = 'internal-1') => ({ type, version: '4', data: { extensions: { [STIX_EXT_OCTI]: { id } } } }) as any;

describe('trackWorkTouchedElement', () => {
  beforeEach(() => {
    vi.mocked(redis.redisGetWorkEventType).mockReset();
    vi.mocked(redis.redisAddWorkTouchedElement).mockReset();
    resetWorkEventTypeCache();
  });

  it('should ignore events outside of a work', async () => {
    await trackWorkTouchedElement(testContext, event('create'));
    expect(redis.redisGetWorkEventType).not.toHaveBeenCalled();
    expect(redis.redisAddWorkTouchedElement).not.toHaveBeenCalled();
  });

  it('should ignore non enrichment works', async () => {
    vi.mocked(redis.redisGetWorkEventType).mockResolvedValue('EXTERNAL_IMPORT');
    await trackWorkTouchedElement({ ...testContext, workId: 'work_a' }, event('create'));
    expect(redis.redisAddWorkTouchedElement).not.toHaveBeenCalled();
  });

  it('should record create and update events of enrichment works', async () => {
    vi.mocked(redis.redisGetWorkEventType).mockResolvedValue('INTERNAL_ENRICHMENT');
    const context = { ...testContext, workId: 'work_b' };
    await trackWorkTouchedElement(context, event('create', 'id-1'));
    await trackWorkTouchedElement(context, event('update', 'id-2'));
    expect(redis.redisAddWorkTouchedElement).toHaveBeenCalledWith('work_b', 'id-1');
    expect(redis.redisAddWorkTouchedElement).toHaveBeenCalledWith('work_b', 'id-2');
  });

  it('should ignore delete and merge events', async () => {
    vi.mocked(redis.redisGetWorkEventType).mockResolvedValue('INTERNAL_ENRICHMENT');
    const context = { ...testContext, workId: 'work_c' };
    await trackWorkTouchedElement(context, event('delete'));
    await trackWorkTouchedElement(context, event('merge'));
    expect(redis.redisAddWorkTouchedElement).not.toHaveBeenCalled();
  });

  it('should resolve the work type once per work', async () => {
    vi.mocked(redis.redisGetWorkEventType).mockResolvedValue('INTERNAL_ENRICHMENT');
    const context = { ...testContext, workId: 'work_d' };
    await trackWorkTouchedElement(context, event('create', 'id-1'));
    await trackWorkTouchedElement(context, event('create', 'id-2'));
    expect(redis.redisGetWorkEventType).toHaveBeenCalledTimes(1);
  });

  it('should never throw when redis fails', async () => {
    vi.mocked(redis.redisGetWorkEventType).mockRejectedValue(new Error('redis down'));
    const warnSpy = vi.spyOn(logApp, 'warn').mockImplementation(() => logApp);
    await expect(trackWorkTouchedElement({ ...testContext, workId: 'work_e' }, event('create'))).resolves.toBeUndefined();
    expect(warnSpy).toHaveBeenCalledWith('[WORK] Unable to track touched element', expect.objectContaining({ workId: 'work_e' }));
    warnSpy.mockRestore();
  });
});

describe('clearCompletedWorkTouchedElements', () => {
  beforeEach(() => {
    vi.mocked(redis.redisDeleteWorkTouchedElements).mockReset().mockResolvedValue(undefined);
  });

  it('should delete the touched set of an enrichment work', async () => {
    await clearCompletedWorkTouchedElements({ internal_id: 'work_f', event_type: 'INTERNAL_ENRICHMENT' });
    expect(redis.redisDeleteWorkTouchedElements).toHaveBeenCalledWith(['work_f']);
  });

  it('should leave other works untouched', async () => {
    await clearCompletedWorkTouchedElements({ internal_id: 'work_g', event_type: 'EXTERNAL_IMPORT' });
    expect(redis.redisDeleteWorkTouchedElements).not.toHaveBeenCalled();
  });

  it('should never throw when redis fails', async () => {
    vi.mocked(redis.redisDeleteWorkTouchedElements).mockRejectedValue(new Error('redis down'));
    const warnSpy = vi.spyOn(logApp, 'warn').mockImplementation(() => logApp);
    await expect(clearCompletedWorkTouchedElements({ id: 'work_h', event_type: 'INTERNAL_ENRICHMENT' })).resolves.toBeUndefined();
    expect(warnSpy).toHaveBeenCalledWith('[WORK] Unable to clean the touched elements of a completed work', expect.objectContaining({ workId: 'work_h' }));
    warnSpy.mockRestore();
  });
});

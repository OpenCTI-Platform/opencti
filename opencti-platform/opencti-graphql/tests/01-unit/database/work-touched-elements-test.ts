import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as redis from '../../../src/database/redis';
import { clearCompletedWorkTouchedElements, resetWorkTrackedCache, trackWorkTouchedElement } from '../../../src/database/work-touched-elements';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';
import { testContext } from '../../utils/testQuery';
import { logApp } from '../../../src/config/conf';

vi.mock('../../../src/database/redis', async (importOriginal) => {
  const actual: object = await importOriginal();
  return { ...actual, redisGetWorkTrackingInfo: vi.fn(), redisAddWorkTouchedElement: vi.fn(), redisDeleteWorkTouchedElements: vi.fn() };
});

/** Build a minimal stream event carrying the given internal id. */
const event = (type: string, id = 'internal-1') => ({ type, version: '4', data: { extensions: { [STIX_EXT_OCTI]: { id } } } }) as any;

const investigationEnrichment = { eventType: 'INTERNAL_ENRICHMENT', investigationId: 'investigation-1' };

describe('trackWorkTouchedElement', () => {
  beforeEach(() => {
    vi.mocked(redis.redisGetWorkTrackingInfo).mockReset();
    vi.mocked(redis.redisAddWorkTouchedElement).mockReset();
    resetWorkTrackedCache();
  });

  it('should ignore events outside of a work', async () => {
    await trackWorkTouchedElement(testContext, event('create'));
    expect(redis.redisGetWorkTrackingInfo).not.toHaveBeenCalled();
    expect(redis.redisAddWorkTouchedElement).not.toHaveBeenCalled();
  });

  it('should ignore non enrichment works', async () => {
    vi.mocked(redis.redisGetWorkTrackingInfo).mockResolvedValue({ eventType: 'EXTERNAL_IMPORT', investigationId: 'investigation-1' });
    await trackWorkTouchedElement({ ...testContext, workId: 'work_a' }, event('create'));
    expect(redis.redisAddWorkTouchedElement).not.toHaveBeenCalled();
  });

  it('should ignore enrichment works not triggered from an investigation', async () => {
    vi.mocked(redis.redisGetWorkTrackingInfo).mockResolvedValue({ eventType: 'INTERNAL_ENRICHMENT', investigationId: null });
    await trackWorkTouchedElement({ ...testContext, workId: 'work_i' }, event('create'));
    expect(redis.redisAddWorkTouchedElement).not.toHaveBeenCalled();
  });

  it('should record create and update events of investigation enrichment works', async () => {
    vi.mocked(redis.redisGetWorkTrackingInfo).mockResolvedValue(investigationEnrichment);
    const context = { ...testContext, workId: 'work_b' };
    await trackWorkTouchedElement(context, event('create', 'id-1'));
    await trackWorkTouchedElement(context, event('update', 'id-2'));
    expect(redis.redisAddWorkTouchedElement).toHaveBeenCalledWith('work_b', 'id-1');
    expect(redis.redisAddWorkTouchedElement).toHaveBeenCalledWith('work_b', 'id-2');
  });

  it('should ignore delete and merge events', async () => {
    vi.mocked(redis.redisGetWorkTrackingInfo).mockResolvedValue(investigationEnrichment);
    const context = { ...testContext, workId: 'work_c' };
    await trackWorkTouchedElement(context, event('delete'));
    await trackWorkTouchedElement(context, event('merge'));
    expect(redis.redisAddWorkTouchedElement).not.toHaveBeenCalled();
  });

  it('should resolve whether a work is tracked once per work', async () => {
    vi.mocked(redis.redisGetWorkTrackingInfo).mockResolvedValue(investigationEnrichment);
    const context = { ...testContext, workId: 'work_d' };
    await trackWorkTouchedElement(context, event('create', 'id-1'));
    await trackWorkTouchedElement(context, event('create', 'id-2'));
    expect(redis.redisGetWorkTrackingInfo).toHaveBeenCalledTimes(1);
  });

  it('should cache works that are not tracked', async () => {
    vi.mocked(redis.redisGetWorkTrackingInfo).mockResolvedValue({ eventType: 'INTERNAL_ENRICHMENT', investigationId: null });
    const context = { ...testContext, workId: 'work_j' };
    await trackWorkTouchedElement(context, event('create', 'id-1'));
    await trackWorkTouchedElement(context, event('create', 'id-2'));
    expect(redis.redisGetWorkTrackingInfo).toHaveBeenCalledTimes(1);
  });

  it('should never throw when redis fails', async () => {
    vi.mocked(redis.redisGetWorkTrackingInfo).mockRejectedValue(new Error('redis down'));
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

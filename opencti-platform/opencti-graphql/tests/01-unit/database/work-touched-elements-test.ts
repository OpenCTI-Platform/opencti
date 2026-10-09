import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as redis from '../../../src/database/redis';
import { resetWorkEventTypeCache, trackWorkTouchedElement } from '../../../src/database/work-touched-elements';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';
import { testContext } from '../../utils/testQuery';
import { logApp } from '../../../src/config/conf';

vi.mock('../../../src/database/redis', async (importOriginal) => {
  const actual: object = await importOriginal();
  return { ...actual, redisGetWorkEventType: vi.fn(), redisAddWorkTouchedElement: vi.fn() };
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

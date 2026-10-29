import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as redis from '../../../src/database/redis';
import { buildEnrichmentCompletion, resetWorkTrackedCache, trackWorkTouchedElement } from '../../../src/database/work-touched-elements';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';
import { testContext } from '../../utils/testQuery';
import { logApp } from '../../../src/config/conf';

vi.mock('../../../src/database/redis', async (importOriginal) => {
  const actual: object = await importOriginal();
  return { ...actual, redisGetWorkTrackingInfo: vi.fn(), redisAddWorkTouchedElement: vi.fn(), redisGetWorkTouchedElements: vi.fn() };
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

describe('buildEnrichmentCompletion', () => {
  const enrichmentWork = { internal_id: 'work_k', event_type: 'INTERNAL_ENRICHMENT', investigation_id: 'investigation-1' };

  beforeEach(() => {
    vi.mocked(redis.redisGetWorkTouchedElements).mockReset().mockResolvedValue({ touched_ids: ['id-1', 'id-2'] });
  });

  /** Tell whether the completion fragment sets the investigation status. */
  const setsToReview = (source: string) => source.includes('investigation_status');

  it('should leave other works untouched', async () => {
    const completion = await buildEnrichmentCompletion({ internal_id: 'work_l', event_type: 'EXTERNAL_IMPORT' });
    expect(completion).toEqual({ source: '', params: {} });
    expect(redis.redisGetWorkTouchedElements).not.toHaveBeenCalled();
  });

  it('should replace the persisted ids with the ids read from redis', async () => {
    const completion = await buildEnrichmentCompletion({ ...enrichmentWork, touched_ids: ['id-1'] });
    expect(completion.source).toContain('ctx._source.touched_ids = params.touched_ids;');
    expect(completion.params).toEqual({ touched_ids: ['id-1', 'id-2'] });
  });

  it('should put a work of an investigation to review at its first completion, even with nothing touched', async () => {
    vi.mocked(redis.redisGetWorkTouchedElements).mockResolvedValue({ touched_ids: [] });
    const completion = await buildEnrichmentCompletion(enrichmentWork);
    expect(setsToReview(completion.source)).toBe(true);
  });

  it('should put a reviewed work back to review when new ids were touched', async () => {
    const completion = await buildEnrichmentCompletion({ ...enrichmentWork, investigation_status: 'DONE', touched_ids: ['id-1'] });
    expect(setsToReview(completion.source)).toBe(true);
  });

  it('should keep the review status when nothing new was touched', async () => {
    const completion = await buildEnrichmentCompletion({ ...enrichmentWork, investigation_status: 'DONE', touched_ids: ['id-1', 'id-2'] });
    expect(setsToReview(completion.source)).toBe(false);
  });

  it('should leave a work outside any investigation without status', async () => {
    const completion = await buildEnrichmentCompletion({ internal_id: 'work_m', event_type: 'INTERNAL_ENRICHMENT' });
    expect(setsToReview(completion.source)).toBe(false);
  });
});

import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as redis from '../../../src/database/redis';
import { buildEnrichmentCompletion, trackWorkTouchedElement } from '../../../src/database/work-touched-elements';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';
import { testContext } from '../../utils/testQuery';
import { logApp } from '../../../src/config/conf';

vi.mock('../../../src/database/redis', async (importOriginal) => {
  const actual: object = await importOriginal();
  return { ...actual, redisAddWorkTouchedElements: vi.fn(), redisGetWorkTouchedElements: vi.fn() };
});

/** Build a minimal stream event carrying the given internal id. */
const event = (type: string, id = 'internal-1') => ({ type, version: '4', data: { extensions: { [STIX_EXT_OCTI]: { id } } } }) as any;

/** Build a minimal ref relationship created with an event element. */
const ref = (id: string, fromId: string, toId: string, toType = 'Label') => ({ internal_id: id, fromId, toId, toType });

/** Build the context of a worker processing a tracked work, as createGraphqlContext sets it. */
const trackedContext = (workId: string) => ({ ...testContext, workId, trackWorkTouchedIds: true, enrichedEntityId: 'enriched-1' });

describe('trackWorkTouchedElement', () => {
  beforeEach(() => {
    vi.mocked(redis.redisAddWorkTouchedElements).mockReset();
  });

  it('should ignore events outside of a work', async () => {
    await trackWorkTouchedElement({ ...testContext, trackWorkTouchedIds: true, enrichedEntityId: 'enriched-1' }, event('create'));
    expect(redis.redisAddWorkTouchedElements).not.toHaveBeenCalled();
  });

  it('should ignore works whose touched ids are not tracked', async () => {
    await trackWorkTouchedElement({ ...trackedContext('work_a'), trackWorkTouchedIds: false }, event('create'));
    await trackWorkTouchedElement({ ...testContext, workId: 'work_a', enrichedEntityId: 'enriched-1' }, event('create'));
    expect(redis.redisAddWorkTouchedElements).not.toHaveBeenCalled();
  });

  it('should ignore works without enriched entity', async () => {
    await trackWorkTouchedElement({ ...trackedContext('work_i'), enrichedEntityId: undefined }, event('create'));
    expect(redis.redisAddWorkTouchedElements).not.toHaveBeenCalled();
  });

  it('should record create and update events of tracked works', async () => {
    const context = trackedContext('work_b');
    await trackWorkTouchedElement(context, event('create', 'id-1'));
    await trackWorkTouchedElement(context, event('update', 'id-2'));
    expect(redis.redisAddWorkTouchedElements).toHaveBeenCalledWith('work_b', ['id-1']);
    expect(redis.redisAddWorkTouchedElements).toHaveBeenCalledWith('work_b', ['id-2']);
  });

  it('should ignore events without internal id', async () => {
    await trackWorkTouchedElement(trackedContext('work_r'), { type: 'create', version: '4', data: {} } as any);
    expect(redis.redisAddWorkTouchedElements).not.toHaveBeenCalled();
  });

  it('should record the refs starting or ending on the enriched entity with the event element', async () => {
    const refs = [ref('ref-contains', 'note-1', 'enriched-1', 'IPv4-Addr'), ref('ref-label', 'enriched-1', 'label-1')];
    await trackWorkTouchedElement(trackedContext('work_n'), event('create', 'note-1'), refs);
    expect(redis.redisAddWorkTouchedElements).toHaveBeenCalledWith('work_n', ['note-1', 'ref-contains', 'ref-label']);
  });

  it('should ignore the refs of other entities', async () => {
    await trackWorkTouchedElement(trackedContext('work_o'), event('create', 'malware-1'), [ref('ref-label', 'malware-1', 'label-1')]);
    expect(redis.redisAddWorkTouchedElements).toHaveBeenCalledWith('work_o', ['malware-1']);
  });

  it('should ignore the refs to users, as the investigation expand does', async () => {
    await trackWorkTouchedElement(trackedContext('work_p'), event('update', 'enriched-1'), [ref('ref-assignee', 'enriched-1', 'user-1', 'User')]);
    expect(redis.redisAddWorkTouchedElements).toHaveBeenCalledWith('work_p', ['enriched-1']);
  });

  it('should ignore delete and merge events', async () => {
    const context = trackedContext('work_c');
    await trackWorkTouchedElement(context, event('delete'));
    await trackWorkTouchedElement(context, event('merge'));
    expect(redis.redisAddWorkTouchedElements).not.toHaveBeenCalled();
  });

  it('should never throw when redis fails', async () => {
    vi.mocked(redis.redisAddWorkTouchedElements).mockRejectedValue(new Error('redis down'));
    const warnSpy = vi.spyOn(logApp, 'warn').mockImplementation(() => logApp);
    await expect(trackWorkTouchedElement(trackedContext('work_e'), event('create'))).resolves.toBeUndefined();
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

  it('should leave works of other kinds untouched', async () => {
    const completion = await buildEnrichmentCompletion({ ...enrichmentWork, internal_id: 'work_l', event_type: 'EXTERNAL_IMPORT' });
    expect(completion).toEqual({ source: '', params: {} });
    expect(redis.redisGetWorkTouchedElements).not.toHaveBeenCalled();
  });

  it('should leave enrichment works outside any investigation untouched', async () => {
    const completion = await buildEnrichmentCompletion({ internal_id: 'work_m', event_type: 'INTERNAL_ENRICHMENT' });
    expect(completion).toEqual({ source: '', params: {} });
    expect(redis.redisGetWorkTouchedElements).not.toHaveBeenCalled();
  });

  it('should replace the persisted ids with the ids read from redis', async () => {
    const completion = await buildEnrichmentCompletion({ ...enrichmentWork, touched_ids: ['id-1'] });
    expect(redis.redisGetWorkTouchedElements).toHaveBeenCalledWith('work_k');
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
});

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { elBulk, elRawDeleteByQuery } from '../../../../src/database/engine';
import { internalFindByIds } from '../../../../src/database/middleware-loader';
import { huntHitRecordId, purgeExpiredHuntHitRecords, recordHuntHits } from '../../../../src/modules/hunt/huntHitRecord/huntHitRecord-domain';
import { testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/engine')>(),
  elBulk: vi.fn(),
  elRawDeleteByQuery: vi.fn(),
  prepareElementForIndexing: vi.fn(async (element: object) => ({ ...element })),
}));

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  internalFindByIds: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-lock', () => ({
  withHuntLock: vi.fn((_key: string, action: () => Promise<unknown>) => action()),
}));

const NOW = '2026-10-07T10:30:00.000Z';
// Late evidence of an event observed long before the retention of the known hits
const OBSERVED = '2025-01-01T08:00:00.000Z';

interface WrittenHit {
  params: Record<string, unknown>;
  source: string;
  upsert: Record<string, unknown>;
}

const writtenHit = (): WrittenHit => {
  const { body } = vi.mocked(elBulk).mock.calls[0][1] as { body: [unknown, { script: { source: string; params: Record<string, unknown> }; upsert: Record<string, unknown> }] };
  return { params: body[1].script.params, source: body[1].script.source, upsert: body[1].upsert };
};

describe('Retention of the known hits', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date(NOW));
    vi.mocked(elBulk).mockReset();
    vi.mocked(elRawDeleteByQuery).mockReset();
    vi.mocked(internalFindByIds).mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should date a hit by its observation and record it when the run is processed, for a new hit', async () => {
    vi.mocked(internalFindByIds).mockResolvedValue([]);
    expect(await recordHuntHits(testContext, { huntId: 'hunt-1', securityPlatformId: 'platform-1', runId: 'run-1', keys: ['hit-1'], seenAt: OBSERVED }))
      .toEqual({ newCount: 1, recurringCount: 0 });
    const { params, upsert } = writtenHit();
    expect(upsert).toMatchObject({ first_seen: OBSERVED, last_seen: OBSERVED, created_at: NOW, updated_at: NOW });
    expect(params).toMatchObject({ run_id: 'run-1', seen_at: OBSERVED, recorded_at: NOW });
  });

  it('should record a known hit found again by late evidence when it is processed, whatever its observation date', async () => {
    const known = { internal_id: huntHitRecordId('hunt-1', 'platform-1', 'hit-1').internalId, hit_key: 'hit-1', first_run_id: 'run-0', last_run_id: 'run-0', counted_run_ids: ['run-0'] };
    vi.mocked(internalFindByIds).mockResolvedValue([known] as never);
    expect(await recordHuntHits(testContext, { huntId: 'hunt-1', securityPlatformId: 'platform-1', runId: 'run-1', keys: ['hit-1'], seenAt: OBSERVED }))
      .toEqual({ newCount: 0, recurringCount: 1 });
    const { params, source } = writtenHit();
    expect(params).toMatchObject({ seen_at: OBSERVED, recorded_at: NOW });
    // The latest observation only moves forward, the recording time follows every run counted
    expect(source).toContain('ctx._source.updated_at = params.recorded_at;');
    expect(source).not.toContain('ctx._source.updated_at = params.seen_at;');
  });

  it('should forget the hits no run was recorded finding within the retention, never by their observation date', async () => {
    const before = '2025-10-07T10:30:00.000Z';
    await purgeExpiredHuntHitRecords(before);
    const { body } = vi.mocked(elRawDeleteByQuery).mock.calls[0][0] as { body: { query: { bool: { filter: unknown[] } } } };
    expect(body.query.bool.filter).toContainEqual({ range: { updated_at: { lt: before } } });
    expect(JSON.stringify(body.query.bool.filter)).not.toContain('last_seen');
  });
});

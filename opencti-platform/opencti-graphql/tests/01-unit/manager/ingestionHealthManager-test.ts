import { beforeEach, describe, expect, it, vi } from 'vitest';
import { logApp } from '../../../src/config/conf';
import { elReplace } from '../../../src/database/engine';
import { evaluateIngestionSource, ingestionHealthHandler } from '../../../src/manager/ingestionHealthManager';
import { collectIngestionSources } from '../../../src/modules/ingestionHealth/ingestionHealth-domain';
import { redisGetIngestionHealthLastRun, redisSetIngestionHealthLastRun, redisSetIngestionHealthObservation } from '../../../src/modules/ingestionHealth/ingestionHealth-redis';

vi.mock('../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<any>()),
  elReplace: vi.fn(),
}));
vi.mock('../../../src/modules/ingestionHealth/ingestionHealth-domain', async (importOriginal) => ({
  ...(await importOriginal<any>()),
  collectIngestionSources: vi.fn(),
}));
vi.mock('../../../src/modules/ingestionHealth/ingestionHealth-redis', () => ({
  redisGetIngestionHealthObservation: vi.fn(),
  redisSetIngestionHealthObservation: vi.fn(),
  redisDeleteIngestionHealthObservation: vi.fn(),
  redisGetIngestionHealthLastRun: vi.fn(),
  redisSetIngestionHealthLastRun: vi.fn(),
}));

const NOW = new Date('2026-10-07T12:00:00.000Z');
const SINCE = '2026-10-07T10:05:00.000Z';
const LAST_SEEN = '2026-10-07T10:00:00.000Z';
const SUMMARY = `No ping received since ${LAST_SEEN}`;
const CHECKS = JSON.stringify([{ kind: 'runtime', code: 'NO_HEARTBEAT', severity: 'blocking', params: { last_seen: LAST_SEEN }, message: SUMMARY }]);
const heartbeat = { last_seen_at: LAST_SEEN, close_pings: 3 };
// A connector that pinged every 40 seconds and has been silent for 2 hours
const source = (id: string, cached: Record<string, unknown> = {}, previousHeartbeat: any = heartbeat, running = true) => ({
  connector: { _index: 'opencti_internal_objects-000001', internal_id: id, name: `Connector ${id}`, ...cached } as any,
  input: { running, run_and_terminate: false, last_seen_at: new Date(LAST_SEEN), pings_regularly: true },
  previous_heartbeat: previousHeartbeat,
  heartbeat,
});
const cachedCritical = { ingestion_health_status: 'critical', ingestion_health_since: SINCE, ingestion_health_summary: SUMMARY, ingestion_health_checks: CHECKS };

describe('Ingestion health manager', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should cache the new verdict with only the ingestion health fields when the status changes', async () => {
    expect(await evaluateIngestionSource({} as any, source('a', { ingestion_health_status: 'unknown', ingestion_health_since: SINCE }), NOW)).toBe(true);
    // Only these four keys: the cache write must never move updated_at nor touch any other field
    expect(elReplace).toHaveBeenCalledWith(expect.anything(), 'opencti_internal_objects-000001', 'a', {
      doc: { ingestion_health_status: 'critical', ingestion_health_since: NOW.toISOString(), ingestion_health_summary: SUMMARY, ingestion_health_checks: CHECKS },
    });
  });

  it('should cache the verdict of a connector never evaluated before', async () => {
    expect(await evaluateIngestionSource({} as any, source('a'), NOW)).toBe(true);
  });

  it('should write nothing in the index when the status, the summary and the checks did not change', async () => {
    expect(await evaluateIngestionSource({} as any, source('a', cachedCritical), NOW)).toBe(false);
    expect(elReplace).not.toHaveBeenCalled();
  });

  it('should keep since when only the summary or the checks changed', async () => {
    // Stopped by a person while already stopped, the heartbeat being lost meanwhile
    const cachedStopped = { ingestion_health_status: 'stopped', ingestion_health_since: SINCE, ingestion_health_summary: 'Stopped by a user', ingestion_health_checks: '[]' };
    expect(await evaluateIngestionSource({} as any, source('a', cachedStopped, heartbeat, false), NOW)).toBe(true);
    expect(elReplace).toHaveBeenCalledWith(expect.anything(), 'opencti_internal_objects-000001', 'a', {
      doc: { ingestion_health_status: 'stopped', ingestion_health_since: SINCE, ingestion_health_summary: 'Stopped by a user', ingestion_health_checks: CHECKS },
    });
  });

  it('should save the heartbeat observation only when it changed', async () => {
    await evaluateIngestionSource({} as any, source('a', cachedCritical), NOW);
    expect(redisSetIngestionHealthObservation).not.toHaveBeenCalled();
    await evaluateIngestionSource({} as any, source('b', cachedCritical, null), NOW);
    expect(redisSetIngestionHealthObservation).toHaveBeenCalledWith('b', heartbeat);
  });

  it('should keep evaluating the other connectors when one fails', async () => {
    (collectIngestionSources as any).mockResolvedValue([source('a'), source('b')]);
    (elReplace as any).mockRejectedValueOnce(new Error('version conflict'));
    const warnSpy = vi.spyOn(logApp, 'warn');
    await ingestionHealthHandler();
    expect(elReplace).toHaveBeenCalledTimes(2);
    expect(warnSpy).toHaveBeenCalledWith('[OPENCTI-MODULE] Ingestion health evaluation error', expect.objectContaining({ id: 'a' }));
  });

  describe('blind periods of the manager itself', () => {
    beforeEach(() => {
      (collectIngestionSources as any).mockResolvedValue([]);
    });

    // The default period (config/default.json): 60 seconds, so a 120 seconds close-pings bound
    it('should not consider itself blind when its last full cycle started less than 120 seconds ago', async () => {
      (redisGetIngestionHealthLastRun as any).mockResolvedValue(new Date(Date.now() - 60 * 1000));
      await ingestionHealthHandler();
      expect(collectIngestionSources).toHaveBeenCalledWith(expect.anything(), { boundSeconds: 120, managerWasBlind: false });
    });

    it('should consider itself blind after more than 120 seconds without a full cycle, or with no trace of one', async () => {
      (redisGetIngestionHealthLastRun as any).mockResolvedValue(new Date(Date.now() - 5 * 60 * 1000));
      await ingestionHealthHandler();
      expect(collectIngestionSources).toHaveBeenLastCalledWith(expect.anything(), { boundSeconds: 120, managerWasBlind: true });
      (redisGetIngestionHealthLastRun as any).mockResolvedValue(null);
      await ingestionHealthHandler();
      expect(collectIngestionSources).toHaveBeenLastCalledWith(expect.anything(), { boundSeconds: 120, managerWasBlind: true });
    });

    it('should record the start time of a full cycle, and nothing for a cycle that could not list the connectors', async () => {
      await ingestionHealthHandler();
      expect(redisSetIngestionHealthLastRun).toHaveBeenCalledTimes(1);
      (collectIngestionSources as any).mockRejectedValueOnce(new Error('index unavailable'));
      await expect(ingestionHealthHandler()).rejects.toThrow('index unavailable');
      expect(redisSetIngestionHealthLastRun).toHaveBeenCalledTimes(1);
    });

    it('should record the start time of the cycle, not its end', async () => {
      vi.useFakeTimers();
      try {
        const start = new Date('2026-10-07T12:00:00.000Z');
        vi.setSystemTime(start);
        (collectIngestionSources as any).mockImplementationOnce(async () => {
          // The cycle takes 30 seconds
          vi.setSystemTime(new Date(start.getTime() + 30 * 1000));
          return [];
        });
        await ingestionHealthHandler();
        expect(redisSetIngestionHealthLastRun).toHaveBeenCalledTimes(1);
        expect(redisSetIngestionHealthLastRun).toHaveBeenCalledWith(start);
      } finally {
        vi.useRealTimers();
      }
    });

    it('should record the cycle even when one evaluation fails', async () => {
      (elReplace as any).mockRejectedValueOnce(new Error('index unavailable'));
      (collectIngestionSources as any).mockResolvedValue([source('a'), source('b')]);
      const warnSpy = vi.spyOn(logApp, 'warn');
      const before = Date.now();
      await ingestionHealthHandler();
      expect(elReplace).toHaveBeenCalledTimes(2); // the second source is still evaluated
      expect(warnSpy).toHaveBeenCalledTimes(1);
      expect(redisSetIngestionHealthLastRun).toHaveBeenCalledTimes(1);
      const recorded = (redisSetIngestionHealthLastRun as any).mock.calls[0][0] as Date;
      expect(recorded.getTime()).toBeGreaterThanOrEqual(before);
    });
  });
});

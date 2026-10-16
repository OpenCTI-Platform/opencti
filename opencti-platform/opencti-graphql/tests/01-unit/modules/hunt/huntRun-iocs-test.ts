import { describe, expect, it, vi } from 'vitest';
import { elRawUpdateByQuery } from '../../../../src/database/engine';
import { countIocHits, hasUnsearchedIoc, huntedIocIds, huntRunEntityMatched, mergeHuntIocResults, recordHuntedIocs } from '../../../../src/modules/hunt/huntRun/huntRun-iocs';
import type { HuntIocResult } from '../../../../src/modules/hunt/huntRun/huntRun-types';

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elRawUpdateByQuery: vi.fn(),
}));

const pending = (key: string, value: string): HuntIocResult => ({
  key,
  observable_type: 'IPv4-Addr',
  value,
  source_ids: [`indicator-${key}`],
  verdict: 'pending',
  hits_count: 0,
  hosts: [],
});

describe('Indicator hunt run results', () => {
  it('should keep only the dispatched values and record each verdict', () => {
    const stored = [pending('a', '198.51.100.7'), pending('b', '198.51.100.8'), pending('c', '198.51.100.9'), pending('d', '198.51.100.10')];
    const merged = mergeHuntIocResults(stored, [
      { key: 'a', seen: true, hits_count: 14, first_seen: '2026-10-04T08:00:00Z', last_seen: '2026-10-04T09:30:00Z', hosts: ['WKS-01', 'WKS-01', ' ', 'SRV-02'] },
      { key: 'b', seen: false, hits_count: 0 },
      { key: 'c', searched: false, seen: false, reason: 'IPv4 lookups are not configured' },
      // A value the run was not dispatched with is ignored
      { key: 'z', seen: true, hits_count: 99 },
    ]);
    expect(merged.map((result) => result.verdict)).toEqual(['seen', 'not_seen', 'not_searched', 'not_searched']);
    expect(merged[0]).toMatchObject({ hits_count: 14, hosts: ['WKS-01', 'SRV-02'], first_seen: '2026-10-04T08:00:00.000Z', source_ids: ['indicator-a'] });
    expect(merged[2].reason).toBe('IPv4 lookups are not configured');
    expect(merged[3].reason).toBe('The connector did not report this value');
    expect(countIocHits(merged)).toBe(14);
    expect(hasUnsearchedIoc(merged)).toBe(true);
  });

  it('should count a value seen without a count as one hit and cap its hosts', () => {
    const merged = mergeHuntIocResults([pending('a', '198.51.100.7')], [
      { key: 'a', seen: true, hosts: Array.from({ length: 30 }, (_, index) => `host-${index}`), first_seen: 'not a date' },
    ]);
    expect(merged[0].hits_count).toBe(1);
    expect(merged[0].hosts).toHaveLength(10);
    expect(merged[0].first_seen).toBeNull();
  });

  it('should know that a run where every value was searched without a hit proves something', () => {
    const merged = mergeHuntIocResults([pending('a', '198.51.100.7')], [{ key: 'a', seen: false }]);
    expect(hasUnsearchedIoc(merged)).toBe(false);
    expect(hasUnsearchedIoc(null)).toBe(false);
  });
});

describe('Indicators and observables a run hunted', () => {
  // An indicator found, an observable searched without a hit, an indicator the platform could not search, and a value
  // shared by an indicator and its observable
  const results = mergeHuntIocResults(
    [pending('a', '198.51.100.7'), pending('b', '198.51.100.8'), pending('c', '198.51.100.9'), { ...pending('d', '198.51.100.10'), source_ids: ['indicator-d', 'observable-d'] }],
    [{ key: 'a', seen: true, hits_count: 2 }, { key: 'b', seen: false }, { key: 'c', searched: false }, { key: 'd', seen: false }],
  );
  const completed = { hunt_run_status: 'completed', hits_count: 2, ioc_results: results };

  it('should tell the entities a run searched and those it found, never one it could not search', () => {
    expect(huntedIocIds(results)).toEqual({ huntedIds: ['indicator-a', 'indicator-b', 'indicator-d', 'observable-d'], matchedIds: ['indicator-a'] });
    expect(huntedIocIds(null)).toEqual({ huntedIds: [], matchedIds: [] });
  });

  it('should tell whether a run matched an entity of its hunt', () => {
    expect(huntRunEntityMatched(completed, 'indicator-a')).toBe(true);
    expect(huntRunEntityMatched(completed, 'observable-d')).toBe(false);
    // Not searched: the run proves nothing about it
    expect(huntRunEntityMatched(completed, 'indicator-c')).toBeNull();
    // A report or a threat the values come from, or the source of a hunt without values: matched by the hits of the run
    expect(huntRunEntityMatched(completed, 'report-1')).toBe(true);
    expect(huntRunEntityMatched({ hunt_run_status: 'completed', hits_count: 0, ioc_results: null }, 'malware-1')).toBe(false);
    expect(huntRunEntityMatched({ ...completed, hunt_run_status: 'running' }, 'indicator-a')).toBeNull();
  });

  it('should date the entities a completed run searched, and those it found, without moving a date back', async () => {
    await recordHuntedIocs({ ioc_results: results, completed_at: '2026-10-16T08:00:00.000Z' });
    expect(elRawUpdateByQuery).toHaveBeenCalledTimes(1);
    const { body } = vi.mocked(elRawUpdateByQuery).mock.calls[0][0];
    expect(body.query).toEqual({ terms: { 'internal_id.keyword': ['indicator-a', 'indicator-b', 'indicator-d', 'observable-d'] } });
    expect(body.script.params).toEqual({ at: '2026-10-16T08:00:00.000Z', matched: ['indicator-a'] });
    expect(body.script.source).toContain('compareTo(params.at) < 0');
    // A run that searched nothing writes nothing
    await recordHuntedIocs({ ioc_results: [pending('e', '198.51.100.11')], completed_at: null });
    expect(elRawUpdateByQuery).toHaveBeenCalledTimes(1);
  });
});

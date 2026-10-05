import { describe, expect, it } from 'vitest';
import { countIocHits, hasUnsearchedIoc, mergeHuntIocResults } from '../../../../src/modules/hunt/huntRun/huntRun-iocs';
import type { HuntIocResult } from '../../../../src/modules/hunt/huntRun/huntRun-types';

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

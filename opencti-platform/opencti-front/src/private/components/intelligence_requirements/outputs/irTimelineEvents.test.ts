import { describe, expect, it } from 'vitest';
import { buildHighlights, countByKind, dailyBuckets, timelineEvents, type TimelineMatch, type TimelinePointData } from './irTimelineEvents';

const point = (at: string, score: number, kind: string, trigger: string, extra: Partial<TimelinePointData> = {}): TimelinePointData => ({
  at, score, kind, trigger, eligible: true, status: 'auto', changes: [], ...extra,
});

const vuln = (id: string, history: TimelinePointData[]): TimelineMatch => ({
  id: `m-${id}`, match_entity_id: id, match_entity_type: 'Vulnerability', match_entity_name: id, match_history: history,
});

const ENTRY = 'Entered through "Vulnerabilities"';
const MATCHES = [
  vuln('CVE-1', [
    point('2026-10-28T08:00:00Z', 0, 'entry', ENTRY),
    point('2026-11-21T13:33:00Z', 50, 'fact', 'New related-to relationship', { changes: ['Impact our stack +50'] }),
    point('2026-11-21T13:45:00Z', 100, 'fact', 'Updated: extensions', { changes: ['CISA KEV exploited +50'] }),
  ]),
  vuln('CVE-2', [point('2026-10-28T09:00:00Z', 0, 'entry', ENTRY), point('2026-11-22T10:00:00Z', 0, 'decision', 'Rejected by admin', { status: 'rejected' })]),
  vuln('CVE-3', [point('2026-10-26T10:00:00Z', 60, 'entry', ENTRY), point('2026-11-23T10:00:00Z', 30, 'config', 'Configuration changed', { eligible: false })]),
  vuln('CVE-4', [point('2026-10-28T11:00:00Z', 10, 'entry', ENTRY), point('2026-11-20T10:00:00Z', 20, 'fact', 'New uses relationship')]),
];

describe('timeline of a requirement', () => {
  it('reads each point of the history with the score it comes from and the thresholds it crosses', () => {
    const events = timelineEvents(MATCHES, [80, 50]);
    expect(events.find((e) => e.trigger === 'Updated: extensions')).toMatchObject({ fromScore: 50, toScore: 100, crossed: 80, dropped: null });
    expect(events.find((e) => e.trigger === 'New related-to relationship')).toMatchObject({ fromScore: 0, toScore: 50, crossed: 50 });
    expect(events.find((e) => e.kind === 'config')).toMatchObject({ fromScore: 60, toScore: 30, dropped: 50, eligibility: 'lost' });
    expect(events.find((e) => e.kind === 'entry')?.fromScore).toBeNull();
  });

  it('counts per day what happened in each lane of the time axis', () => {
    const buckets = dailyBuckets(timelineEvents(MATCHES, [80]), '2026-10-27');
    expect(buckets.map((b) => b.day)).toEqual(['2026-10-28', '2026-11-20', '2026-11-21', '2026-11-22', '2026-11-23']);
    expect(buckets[0]).toMatchObject({ entry: 3, up: 0 });
    expect(buckets[2]).toMatchObject({ entry: 0, up: 2, down: 0 });
    expect(buckets[3].decision).toBe(1);
    expect(countByKind(timelineEvents(MATCHES, []), '2026-11-01')).toEqual({ entry: 0, fact: 3, decision: 1, config: 1 });
  });

  it('tells a period in cards: thresholds crossed first, the waves of entries summed up last', () => {
    const cards = buildHighlights(timelineEvents(MATCHES, [80, 50]), { from: null, to: null });
    expect(cards.map((c) => [c.kind, c.threshold])).toEqual([
      ['crossed', 80], ['crossed', 50], ['decision', null], ['moves', null], ['config', null], ['wave', null],
    ]);
    const wave = cards[5];
    expect(wave).toMatchObject({ entityType: 'Vulnerability', days: 2, peak: { day: '2026-10-28', count: 3 } });
    expect(wave.events).toHaveLength(4);
    const day = buildHighlights(timelineEvents(MATCHES, [80, 50]), { from: '2026-11-21', to: '2026-11-22' });
    expect(day.map((c) => c.kind)).toEqual(['crossed', 'crossed']);
  });
});

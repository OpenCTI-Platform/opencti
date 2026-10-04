import { describe, expect, it } from 'vitest';
import { buildTimelineConsistencyFilters, collectTimelineImpacts, isTimelineConsistencyPassDue } from '../../../src/manager/timelineManager';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';
import type { DataEvent, SseEvent } from '../../../src/types/event';

const streamEvent = (data: Record<string, any>): SseEvent<DataEvent> => ({
  id: '1-0',
  event: 'update',
  data: { type: 'update', scope: 'external', version: '4', origin: {}, message: '', data } as any,
});

const newCollector = () => ({ containers: new Set<string>(), contained: new Set<string>(), related: new Set<string>(), references: new Set<string>() });

describe('Timeline manager impact collection', () => {
  it('should directly impact a timeline container', () => {
    const collector = newCollector();
    collectTimelineImpacts(streamEvent({ type: 'case-incident', extensions: { [STIX_EXT_OCTI]: { id: 'case-1', type: 'Case-Incident' } } }), collector);
    expect(Array.from(collector.containers)).toEqual(['case-1']);
    expect(collector.contained.size).toEqual(0);
  });

  it('should follow the object refs of tasks, notes, opinions and reports', () => {
    const collector = newCollector();
    collectTimelineImpacts(streamEvent({ type: 'note', object_refs: ['case-incident--1'], extensions: { [STIX_EXT_OCTI]: { id: 'note-1', type: 'Note' } } }), collector);
    expect(Array.from(collector.references)).toEqual(['case-incident--1']);
  });

  it('should impact incidents linked by a relationship and containers of its elements', () => {
    const collector = newCollector();
    collectTimelineImpacts(streamEvent({
      type: 'relationship',
      extensions: { [STIX_EXT_OCTI]: { id: 'rel-1', type: 'uses', source_ref: 'incident-1', source_type: 'Incident', target_ref: 'ap-1', target_type: 'Attack-Pattern' } },
    }), collector);
    expect(Array.from(collector.containers)).toEqual(['incident-1']);
    // Cases containing either endpoint (here the targeted attack pattern) are impacted too
    expect(Array.from(collector.contained).sort()).toEqual(['ap-1', 'incident-1', 'rel-1']);
  });

  it('should follow the sighted element of a sighting', () => {
    const collector = newCollector();
    collectTimelineImpacts(streamEvent({ type: 'sighting', extensions: { [STIX_EXT_OCTI]: { id: 's-1', type: 'stix-sighting-relationship', sighting_of_ref: 'ind-1' } } }), collector);
    expect(Array.from(collector.contained).sort()).toEqual(['ind-1', 's-1']);
    // Incidents load the platform sightings of their related indicators
    expect(Array.from(collector.related)).toEqual(['ind-1']);
  });

  it('should look for the cases and incidents of any other updated entity', () => {
    const collector = newCollector();
    collectTimelineImpacts(streamEvent({ type: 'malware', extensions: { [STIX_EXT_OCTI]: { id: 'mal-1', type: 'Malware' } } }), collector);
    expect(Array.from(collector.contained)).toEqual(['mal-1']);
    expect(Array.from(collector.related)).toEqual(['mal-1']);
  });

  it('should ignore inferred data and timeline objects', () => {
    const collector = newCollector();
    collectTimelineImpacts(streamEvent({ type: 'malware', extensions: { [STIX_EXT_OCTI]: { id: 'mal-1', type: 'Malware', is_inferred: true } } }), collector);
    collectTimelineImpacts(streamEvent({ type: 'timeline-event', extensions: { [STIX_EXT_OCTI]: { id: 'te-1', type: 'Timeline-Event' } } }), collector);
    collectTimelineImpacts(streamEvent({}), collector);
    expect(collector.contained.size + collector.related.size + collector.containers.size).toEqual(0);
  });
});

describe('Timeline consistency pass schedule', () => {
  const at = (iso: string) => Date.parse(iso);

  it('should run once a day after the configured hour', () => {
    // The first pass (backfill of an existing platform) never waits for the scheduled hour
    expect(isTimelineConsistencyPassDue(null, at('2026-10-03T01:00:00.000Z'), 2)).toBe(true);
    expect(isTimelineConsistencyPassDue(null, at('2026-10-03T02:00:00.000Z'), 2)).toBe(true);
    expect(isTimelineConsistencyPassDue(at('2026-10-03T00:30:00.000Z'), at('2026-10-03T01:00:00.000Z'), 2)).toBe(false);
    expect(isTimelineConsistencyPassDue(at('2026-10-02T02:00:05.000Z'), at('2026-10-03T03:00:00.000Z'), 2)).toBe(true);
    expect(isTimelineConsistencyPassDue(at('2026-10-03T02:00:05.000Z'), at('2026-10-03T23:00:00.000Z'), 2)).toBe(false);
  });

  it('should only schedule the containers changed since the last pass, never computed or older than the max age', () => {
    const filters = buildTimelineConsistencyFilters(at('2026-10-02T02:00:05.000Z'), at('2026-10-03T02:00:00.000Z'), 30);
    expect(filters.mode).toEqual('or');
    expect(filters.filters).toEqual([
      { key: ['updated_at'], operator: 'gte', values: ['2026-10-02T02:00:05.000Z'] },
      { key: ['x_opencti_timeline_anchors.computed_at'], operator: 'nil', values: [] },
      { key: ['x_opencti_timeline_anchors.computed_at'], operator: 'lt', values: ['2026-09-03T02:00:00.000Z'] },
    ]);
  });

  it('should look back one day on the first pass', () => {
    const filters = buildTimelineConsistencyFilters(null, at('2026-10-03T02:00:00.000Z'), 7);
    expect(filters.filters[0].values).toEqual(['2026-10-02T02:00:00.000Z']);
    expect(filters.filters[2].values).toEqual(['2026-09-26T02:00:00.000Z']);
  });
});

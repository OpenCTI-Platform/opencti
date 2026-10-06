import { describe, expect, it } from 'vitest';
import { computeTimelineAnchorBounds, computeTimelineAnchors, diffTimelineAnchors } from '../../../../src/modules/timeline/timeline-anchors';
import { RULE_TASK_CONTAINMENT, RULE_WORKFLOW_CLOSURE } from '../../../../src/modules/timeline/timeline-rules';

const computedAt = '2026-04-01T00:00:00.000Z';

describe('Timeline anchors', () => {
  const events = [
    { lane: 'adversary' as const, kind: 'technique_used' as const, event_time: '2026-03-02T00:00:00.000Z' },
    { lane: 'adversary' as const, kind: 'infrastructure_seen' as const, event_time: '2026-03-01T00:00:00.000Z' },
    { lane: 'adversary' as const, kind: 'sighting' as const, event_time: '2026-02-01T00:00:00.000Z', hidden: true },
    { lane: 'detection' as const, kind: 'sighting' as const, event_time: '2026-03-03T00:00:00.000Z' },
    { lane: 'response' as const, kind: 'case_opened' as const, event_time: '2026-03-04T00:00:00.000Z' },
    { lane: 'response' as const, kind: 'task_completed' as const, rule_id: RULE_TASK_CONTAINMENT, event_time: '2026-03-06T00:00:00.000Z' },
    { lane: 'custom' as const, kind: 'containment' as const, event_time: '2026-03-05T00:00:00.000Z' },
    { lane: 'response' as const, kind: 'status_changed' as const, rule_id: RULE_WORKFLOW_CLOSURE, event_time: '2026-03-08T00:00:00.000Z' },
    { lane: 'response' as const, kind: 'status_changed' as const, rule_id: RULE_WORKFLOW_CLOSURE, event_time: '2026-03-10T00:00:00.000Z' },
  ];

  it('should compute every anchor and ignore hidden events', () => {
    const anchors = computeTimelineAnchors(events, { isClosed: true, computedAt });
    expect(anchors).toEqual({
      first_adversary_activity: '2026-03-01T00:00:00.000Z',
      first_detection: '2026-03-03T00:00:00.000Z',
      first_response: '2026-03-04T00:00:00.000Z',
      containment: '2026-03-05T00:00:00.000Z',
      closure: '2026-03-10T00:00:00.000Z',
      computed_at: computedAt,
      changed_at: computedAt,
    });
  });

  it('should keep the change date while no anchor value moves', () => {
    const first = computeTimelineAnchors(events, { isClosed: false, computedAt });
    const recomputed = computeTimelineAnchors(events, { isClosed: false, computedAt: '2026-04-02T00:00:00.000Z', previous: first });
    expect(recomputed.computed_at).toEqual('2026-04-02T00:00:00.000Z');
    expect(recomputed.changed_at).toEqual(computedAt);
    const closed = computeTimelineAnchors(events, { isClosed: true, computedAt: '2026-04-03T00:00:00.000Z', previous: recomputed });
    expect(closed.changed_at).toEqual('2026-04-03T00:00:00.000Z');
  });

  it('should keep the generation date when the anchors are recomputed between two generations', () => {
    const generated = computeTimelineAnchors(events, { isClosed: false, computedAt });
    // A milestone or a pin recomputes the anchors without regenerating the timeline: computed_at stays the generation date
    const curated = computeTimelineAnchors(events, { isClosed: true, computedAt: '2026-04-05T00:00:00.000Z', generatedAt: generated.computed_at as string, previous: generated });
    expect(curated.computed_at).toEqual(computedAt);
    // while the change date still tells when an anchor value moved
    expect(curated.changed_at).toEqual('2026-04-05T00:00:00.000Z');
  });

  it('should never mark a timeline as generated for a contribution added before its first generation', () => {
    const contributed = computeTimelineAnchors(events, { isClosed: false, computedAt, generatedAt: null });
    expect(contributed.computed_at).toBeNull();
    expect(contributed.changed_at).toEqual(computedAt);
  });

  it('should date the change of anchors stored before the change date existed', () => {
    const legacy = { first_adversary_activity: '2026-03-01T00:00:00.000Z', computed_at: computedAt };
    const anchors = computeTimelineAnchors(events, { isClosed: false, computedAt: '2026-04-02T00:00:00.000Z', previous: legacy });
    expect(anchors.changed_at).toEqual('2026-04-02T00:00:00.000Z');
  });

  it('should not expose a closure while the container is open', () => {
    expect(computeTimelineAnchors(events, { isClosed: false, computedAt }).closure).toBeNull();
  });

  it('should return empty anchors for an empty timeline', () => {
    const anchors = computeTimelineAnchors([], { isClosed: false, computedAt });
    expect(anchors.first_adversary_activity).toBeNull();
    expect(anchors.containment).toBeNull();
  });

  it('should keep counting the derived events beyond the cap of a case between two regenerations', () => {
    // Derived events the cap of the case leaves out of the stored timeline, recorded by the regeneration
    const bounds = computeTimelineAnchorBounds([
      { lane: 'adversary', kind: 'technique_used', event_time: '2026-02-15T00:00:00.000Z' },
      { lane: 'detection', kind: 'sighting', event_time: '2026-03-07T00:00:00.000Z' },
      { lane: 'detection', kind: 'sighting', event_time: '2026-02-20T00:00:00.000Z', hidden: true },
      { lane: 'response', kind: 'status_changed', rule_id: RULE_WORKFLOW_CLOSURE, event_time: '2026-03-12T00:00:00.000Z' },
    ]);
    expect(bounds).toEqual({
      first_adversary_activity: '2026-02-15T00:00:00.000Z',
      first_detection: '2026-03-07T00:00:00.000Z',
      first_response: '2026-03-12T00:00:00.000Z',
      containment: null,
      closure: '2026-03-12T00:00:00.000Z',
    });
    // An analyst hides the only stored detection afterwards: the anchors still read the events beyond the cap
    const stored = events.map((event) => (event.lane === 'detection' ? { ...event, hidden: true } : event));
    expect(computeTimelineAnchors(stored, { isClosed: true, computedAt, bounds })).toMatchObject({
      first_adversary_activity: '2026-02-15T00:00:00.000Z',
      first_detection: '2026-03-07T00:00:00.000Z',
      first_response: '2026-03-04T00:00:00.000Z',
      containment: '2026-03-05T00:00:00.000Z',
      closure: '2026-03-12T00:00:00.000Z',
    });
    expect(computeTimelineAnchors(stored, { isClosed: false, computedAt, bounds }).closure).toBeNull();
  });

  it('should list the anchors that changed', () => {
    const previous = computeTimelineAnchors(events, { isClosed: false, computedAt });
    const next = computeTimelineAnchors(events, { isClosed: true, computedAt: '2026-04-02T00:00:00.000Z' });
    expect(diffTimelineAnchors(previous, next)).toEqual(['closure']);
    expect(diffTimelineAnchors(next, next)).toEqual([]);
    expect(diffTimelineAnchors(undefined, next)).toEqual(['first_adversary_activity', 'first_detection', 'first_response', 'containment', 'closure']);
  });
});

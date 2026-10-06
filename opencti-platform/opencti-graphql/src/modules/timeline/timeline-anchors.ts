import { RULE_TASK_CONTAINMENT, RULE_WORKFLOW_CLOSURE, toTimelineTime } from './timeline-rules';
import type { TimelineAnchorBounds, TimelineAnchorKey, TimelineAnchors, TimelineKindValue, TimelineLaneValue } from './timeline-types';
import { TIMELINE_ANCHOR_KEYS } from './timeline-types';

export interface AnchorEventLike {
  lane: TimelineLaneValue;
  kind: TimelineKindValue;
  rule_id?: string | null;
  event_time: string;
  hidden?: boolean;
}

export interface AnchorComputationContext {
  // closure only exists while the container sits in a final workflow status
  isClosed: boolean;
  computedAt: string;
  // last generation of the timeline from the knowledge, when it is not this computation (a milestone or a pin since);
  // null when the timeline was never generated, so that a first contribution never passes for a generation
  generatedAt?: string | null;
  // anchors stored by the previous computation, changed_at is kept when no anchor value moved
  previous?: Partial<TimelineAnchors> | null;
  // anchor values of the derived events a capped timeline does not store: they count like events
  bounds?: Partial<TimelineAnchorBounds> | null;
}

const minTime = (events: AnchorEventLike[], bound?: string | null): string | null => {
  let min: number | null = bound ? toTimelineTime(bound) : null;
  events.forEach((event) => {
    const time = toTimelineTime(event.event_time);
    if (time !== null && (min === null || time < min)) min = time;
  });
  return min !== null ? new Date(min).toISOString() : null;
};

const maxTime = (events: AnchorEventLike[], bound?: string | null): string | null => {
  let max: number | null = bound ? toTimelineTime(bound) : null;
  events.forEach((event) => {
    const time = toTimelineTime(event.event_time);
    if (time !== null && (max === null || time > max)) max = time;
  });
  return max !== null ? new Date(max).toISOString() : null;
};

/** Return the anchors whose value changed (computed_at and changed_at excluded). */
export const diffTimelineAnchors = (previous: Partial<TimelineAnchors> | null | undefined, next: Pick<TimelineAnchors, TimelineAnchorKey>): TimelineAnchorKey[] => {
  return TIMELINE_ANCHOR_KEYS.filter((key) => {
    const before = previous?.[key] ? new Date(previous[key] as string).getTime() : null;
    const after = next[key] ? new Date(next[key] as string).getTime() : null;
    return before !== after;
  });
};

/**
 * Per-case anchors. Hidden events never contribute: hiding an event is the analyst way to
 * discard noise, so it must not move an anchor.
 * - first_adversary_activity: first event of the adversary lane
 * - first_detection: first event of the detection lane (platform sightings, coverage results, hunts, deployments, manual detections)
 * - first_response: first event of the response lane
 * - containment: first containment milestone or first completion of a task labelled containment
 * - closure: last transition to a final workflow status, only while the container is still closed
 * computed_at is the last generation of the timeline from the knowledge (the consistency pass regenerates the timelines
 * it finds too old), changed_at moves only when one of these values moves: consumers use changed_at as their incremental
 * cursor.
 */
export const computeTimelineAnchors = (events: AnchorEventLike[], context: AnchorComputationContext): TimelineAnchors => {
  const visible = events.filter((event) => !event.hidden);
  const bounds = context.bounds ?? {};
  const values = {
    first_adversary_activity: minTime(visible.filter((e) => e.lane === 'adversary'), bounds.first_adversary_activity),
    first_detection: minTime(visible.filter((e) => e.lane === 'detection'), bounds.first_detection),
    first_response: minTime(visible.filter((e) => e.lane === 'response'), bounds.first_response),
    containment: minTime(visible.filter((e) => e.kind === 'containment' || e.rule_id === RULE_TASK_CONTAINMENT), bounds.containment),
    closure: context.isClosed ? maxTime(visible.filter((e) => e.rule_id === RULE_WORKFLOW_CLOSURE), bounds.closure) : null,
  };
  const previousChangedAt = context.previous?.changed_at;
  const changedAt = previousChangedAt && diffTimelineAnchors(context.previous, values).length === 0 ? previousChangedAt : context.computedAt;
  return { ...values, computed_at: context.generatedAt === undefined ? context.computedAt : context.generatedAt, changed_at: changedAt };
};

/** Anchor values of events whatever the status of their container (the closure applies only while it is closed). */
export const computeTimelineAnchorBounds = (events: AnchorEventLike[]): TimelineAnchorBounds => {
  const anchors = computeTimelineAnchors(events, { isClosed: true, computedAt: new Date(0).toISOString() });
  return {
    first_adversary_activity: anchors.first_adversary_activity,
    first_detection: anchors.first_detection,
    first_response: anchors.first_response,
    containment: anchors.containment,
    closure: anchors.closure,
  };
};

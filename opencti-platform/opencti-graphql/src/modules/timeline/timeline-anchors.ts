import { RULE_TASK_CONTAINMENT, RULE_WORKFLOW_CLOSURE, toTimelineTime } from './timeline-rules';
import type { TimelineAnchorKey, TimelineAnchors, TimelineKindValue, TimelineLaneValue } from './timeline-types';
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
  // anchors stored by the previous computation, changed_at is kept when no anchor value moved
  previous?: Partial<TimelineAnchors> | null;
}

const minTime = (events: AnchorEventLike[]): string | null => {
  let min: number | null = null;
  events.forEach((event) => {
    const time = toTimelineTime(event.event_time);
    if (time !== null && (min === null || time < min)) min = time;
  });
  return min !== null ? new Date(min).toISOString() : null;
};

const maxTime = (events: AnchorEventLike[]): string | null => {
  let max: number | null = null;
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
 * computed_at moves on every computation, changed_at only when one of these values moves: consumers
 * use changed_at as their incremental cursor.
 */
export const computeTimelineAnchors = (events: AnchorEventLike[], context: AnchorComputationContext): TimelineAnchors => {
  const visible = events.filter((event) => !event.hidden);
  const values = {
    first_adversary_activity: minTime(visible.filter((e) => e.lane === 'adversary')),
    first_detection: minTime(visible.filter((e) => e.lane === 'detection')),
    first_response: minTime(visible.filter((e) => e.lane === 'response')),
    containment: minTime(visible.filter((e) => e.kind === 'containment' || e.rule_id === RULE_TASK_CONTAINMENT)),
    closure: context.isClosed ? maxTime(visible.filter((e) => e.rule_id === RULE_WORKFLOW_CLOSURE)) : null,
  };
  const previousChangedAt = context.previous?.changed_at;
  const changedAt = previousChangedAt && diffTimelineAnchors(context.previous, values).length === 0 ? previousChangedAt : context.computedAt;
  return { ...values, computed_at: context.computedAt, changed_at: changedAt };
};

// Timeline of a requirement, read from the dated history of its entities (entry, new fact, decision, configuration).
// Entries come in waves (a catch-up brings dozens of entities the same day): they are grouped per day, criterion and type,
// so that what changed one entity at a time (a score that moves, a decision) stays visible.

export type TimelineKind = 'entry' | 'fact' | 'decision' | 'config';
export const TIMELINE_KINDS: TimelineKind[] = ['entry', 'fact', 'decision', 'config'];

export interface TimelinePointData {
  readonly at: string;
  readonly score: number;
  readonly eligible: boolean;
  readonly status: string;
  readonly kind: string;
  readonly trigger?: string | null;
  readonly changes: readonly string[];
}

export interface TimelineMatch {
  readonly id: string;
  readonly match_entity_id: string;
  readonly match_entity_type: string;
  readonly match_entity_name?: string | null;
  readonly entity?: { readonly representative: { readonly main: string } } | null;
  readonly match_history: readonly TimelinePointData[];
}

export interface TimelineEvent {
  matchId: string;
  entityId: string;
  entityType: string;
  name: string;
  at: string;
  kind: TimelineKind;
  trigger: string;
  changes: readonly string[];
  fromScore: number | null; // null for an entry
  toScore: number;
  crossed: number | null; // highest threshold crossed upwards, if any
  dropped: number | null; // highest threshold crossed downwards, if any
  status: string;
  eligibility: 'lost' | 'regained' | null;
}

export interface TimelineGroup {
  key: string;
  kind: TimelineKind;
  at: string; // the latest event of the group
  trigger: string;
  entityType: string;
  events: TimelineEvent[];
}

export interface TimelineDay {
  day: string; // YYYY-MM-DD
  groups: TimelineGroup[];
}

const asKind = (kind: string): TimelineKind => (TIMELINE_KINDS.includes(kind as TimelineKind) ? kind as TimelineKind : 'fact');

export const timelineEvents = (matches: readonly TimelineMatch[], thresholds: readonly number[]): TimelineEvent[] => matches.flatMap((m) => {
  const points = [...m.match_history].sort((a, b) => a.at.localeCompare(b.at));
  const name = m.match_entity_name ?? m.entity?.representative.main ?? m.match_entity_id;
  return points.map((point, i) => {
    const previous = i > 0 ? points[i - 1] : null;
    const from = previous ? previous.score : null;
    const up = thresholds.filter((t) => from !== null && from < t && point.score >= t);
    const down = thresholds.filter((t) => from !== null && from >= t && point.score < t);
    let eligibility: TimelineEvent['eligibility'] = null;
    if (previous && previous.eligible && !point.eligible) eligibility = 'lost';
    if (previous && !previous.eligible && point.eligible) eligibility = 'regained';
    return {
      matchId: m.id,
      entityId: m.match_entity_id,
      entityType: m.match_entity_type,
      name,
      at: point.at,
      kind: asKind(point.kind),
      trigger: point.trigger ?? '',
      changes: point.changes,
      fromScore: from,
      toScore: point.score,
      crossed: up.length > 0 ? Math.max(...up) : null,
      dropped: down.length > 0 ? Math.max(...down) : null,
      status: point.status,
      eligibility,
    };
  });
});

// region time axis: per day, what happened in each lane
export interface TimelineDayBucket {
  day: string; // YYYY-MM-DD
  entry: number;
  up: number; // score changes upwards
  down: number;
  decision: number;
  config: number;
}

export const dailyBuckets = (events: readonly TimelineEvent[], since: string | null): TimelineDayBucket[] => {
  const days = new Map<string, TimelineDayBucket>();
  events.filter((e) => !since || e.at >= since).forEach((e) => {
    const day = e.at.slice(0, 10);
    const bucket = days.get(day) ?? { day, entry: 0, up: 0, down: 0, decision: 0, config: 0 };
    if (e.kind === 'fact') {
      if (e.toScore >= (e.fromScore ?? 0)) bucket.up += 1;
      else bucket.down += 1;
    } else {
      bucket[e.kind] += 1;
    }
    days.set(day, bucket);
  });
  return Array.from(days.values()).sort((a, b) => a.day.localeCompare(b.day));
};
// endregion

// region highlights: the period told in a few cards, what deserves attention first
export type HighlightKind = 'crossed' | 'dropped' | 'decision' | 'moves' | 'config' | 'wave';

export interface Highlight {
  key: string;
  kind: HighlightKind;
  at: string; // the latest event of the card
  events: TimelineEvent[];
  threshold: number | null; // crossed or dropped
  trigger: string;
  entityType: string | null; // a wave of entries is of one type
  peak: { day: string; count: number } | null; // the busiest day of a wave
  days: number; // days a wave or a recalculation spreads over
}

const ORDER: HighlightKind[] = ['crossed', 'dropped', 'decision', 'moves', 'config', 'wave'];

const latest = (events: readonly TimelineEvent[]) => events.reduce((max, e) => (e.at > max ? e.at : max), '');

const grouped = (events: readonly TimelineEvent[], kind: HighlightKind, keyOf: (e: TimelineEvent) => string): Highlight[] => {
  const groups = new Map<string, TimelineEvent[]>();
  events.forEach((e) => groups.set(keyOf(e), [...(groups.get(keyOf(e)) ?? []), e]));
  return Array.from(groups.entries()).map(([key, list]) => {
    const perDay = new Map<string, number>();
    list.forEach((e) => perDay.set(e.at.slice(0, 10), (perDay.get(e.at.slice(0, 10)) ?? 0) + 1));
    const [peakDay, peakCount] = Array.from(perDay.entries()).sort((a, b) => b[1] - a[1] || b[0].localeCompare(a[0]))[0];
    return {
      key: `${kind}|${key}`,
      kind,
      at: latest(list),
      events: [...list].sort((a, b) => b.at.localeCompare(a.at)),
      threshold: null,
      trigger: list[0].trigger,
      entityType: kind === 'wave' ? list[0].entityType : null,
      peak: { day: peakDay, count: peakCount },
      days: perDay.size,
    };
  });
};

/**
 * The cards of a period (from <= at < to): thresholds crossed first, then drops, decisions, the other score changes,
 * the recalculations after a change of configuration, and the waves of entries summed up per trigger and type.
 */
export const buildHighlights = (events: readonly TimelineEvent[], range: { from: string | null; to: string | null }): Highlight[] => {
  const scoped = events.filter((e) => (!range.from || e.at >= range.from) && (!range.to || e.at < range.to));
  const single = (e: TimelineEvent, kind: HighlightKind, threshold: number | null): Highlight => ({
    key: `${kind}|${e.matchId}|${e.at}`, kind, at: e.at, events: [e], threshold, trigger: e.trigger, entityType: e.entityType, peak: null, days: 1,
  });
  const facts = scoped.filter((e) => e.kind === 'fact');
  const crossed = facts.filter((e) => e.crossed !== null).map((e) => single(e, 'crossed', e.crossed));
  const dropped = facts.filter((e) => e.crossed === null && (e.dropped !== null || e.eligibility === 'lost')).map((e) => single(e, 'dropped', e.dropped));
  const decisions = scoped.filter((e) => e.kind === 'decision').map((e) => single(e, 'decision', null));
  const others = facts.filter((e) => e.crossed === null && e.dropped === null && e.eligibility !== 'lost');
  const moves = others.length > 0 ? grouped(others, 'moves', () => 'all') : [];
  const config = grouped(scoped.filter((e) => e.kind === 'config'), 'config', (e) => e.trigger);
  const waves = grouped(scoped.filter((e) => e.kind === 'entry'), 'wave', (e) => `${e.trigger}|${e.entityType}`);
  return [...crossed, ...dropped, ...decisions, ...moves, ...config, ...waves].sort((a, b) => {
    const byKind = ORDER.indexOf(a.kind) - ORDER.indexOf(b.kind);
    if (byKind !== 0) return byKind;
    if ((a.threshold ?? 0) !== (b.threshold ?? 0)) return (b.threshold ?? 0) - (a.threshold ?? 0);
    return b.at.localeCompare(a.at);
  });
};
// endregion

export const countByKind = (events: readonly TimelineEvent[], since: string | null) => TIMELINE_KINDS.reduce<Record<TimelineKind, number>>(
  (counts, kind) => ({ ...counts, [kind]: events.filter((e) => e.kind === kind && (!since || e.at >= since)).length }),
  { entry: 0, fact: 0, decision: 0, config: 0 },
);

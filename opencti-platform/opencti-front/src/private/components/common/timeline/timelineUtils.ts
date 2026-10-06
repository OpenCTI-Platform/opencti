// Pure helpers of the incident and case timeline (no React, no Relay): constants shared with the
// backend enums, URL view state, time domain math, grouping buckets, lane layout and export helpers.

// Display order of the lanes, from the attack to the response
export const TIMELINE_LANES = ['adversary', 'detection', 'response', 'evidence', 'knowledge', 'custom'] as const;
export type TimelineLane = typeof TIMELINE_LANES[number];

export const TIMELINE_LANE_LABELS: Record<TimelineLane, string> = {
  adversary: 'Adversary',
  detection: 'Detection',
  response: 'Response',
  evidence: 'Evidence',
  knowledge: 'Knowledge',
  custom: 'Custom',
};

export const TIMELINE_MILESTONE_KINDS = ['milestone', 'containment', 'eradication', 'recovery', 'notification'] as const;

export const TIMELINE_KIND_LABELS: Record<string, string> = {
  technique_used: 'Technique used',
  observed_window: 'Observation window',
  sighting: 'Sighting',
  infrastructure_seen: 'Infrastructure seen',
  malware_seen: 'Malware seen',
  threat_seen: 'Threat seen',
  incident_seen: 'Incident seen',
  indicator_valid: 'Indicator validity',
  report_published: 'Report published',
  reference_published: 'Reference published',
  file_uploaded: 'File uploaded',
  case_opened: 'Case opened',
  task_created: 'Task created',
  task_due: 'Task due',
  task_completed: 'Task completed',
  status_changed: 'Status changed',
  assigned: 'Assignment',
  note_added: 'Note added',
  opinion_added: 'Opinion added',
  investigation_step: 'Investigation step',
  object_added: 'Object added',
  relation_created: 'Relationship created',
  merged: 'Merge',
  coverage_result: 'Coverage result',
  hunt_run: 'Hunt run',
  deployment: 'Deployment',
  milestone: 'Milestone',
  containment: 'Containment',
  eradication: 'Eradication',
  recovery: 'Recovery',
  notification: 'Notification',
};
export const TIMELINE_KINDS = Object.keys(TIMELINE_KIND_LABELS);

export const TIMELINE_ANCHOR_KEYS = ['first_adversary_activity', 'first_detection', 'first_response', 'containment', 'closure'] as const;
export type TimelineAnchorKey = typeof TIMELINE_ANCHOR_KEYS[number];
export const TIMELINE_ANCHOR_LABELS: Record<TimelineAnchorKey, string> = {
  first_adversary_activity: 'First adversary activity',
  first_detection: 'First detection',
  first_response: 'First response',
  containment: 'Containment',
  closure: 'Closure',
};

export const TIMELINE_PRECISIONS = ['exact', 'hour', 'day', 'approximate'] as const;
export type TimelinePrecision = typeof TIMELINE_PRECISIONS[number];
export const TIMELINE_PRECISION_LABELS: Record<TimelinePrecision, string> = {
  exact: 'Exact',
  hour: 'Hour',
  day: 'Day',
  approximate: 'Approximate',
};

export const TIMELINE_GROUPINGS = ['hour', 'day', 'week'] as const;
export type TimelineGrouping = typeof TIMELINE_GROUPINGS[number];
export const TIMELINE_GROUPING_LABELS: Record<TimelineGrouping, string> = { hour: 'Hour', day: 'Day', week: 'Week' };

export const TIMELINE_ZOOM_WINDOWS = ['fit', 'day', 'week', 'month', 'quarter', 'year'] as const;
export type TimelineZoomWindow = typeof TIMELINE_ZOOM_WINDOWS[number];
export const TIMELINE_ZOOM_LABELS: Record<TimelineZoomWindow, string> = {
  fit: 'Fit',
  day: 'Day',
  week: 'Week',
  month: 'Month',
  quarter: 'Quarter',
  year: 'Year',
};

export const TIMELINE_SOURCES = ['derived', 'manual'] as const;
export type TimelineSource = typeof TIMELINE_SOURCES[number];

export type TimelineExportFormat = 'csv' | 'pdf' | 'svg' | 'png';

// Entity types carrying a timeline
export const TIMELINE_CONTAINER_TYPES = ['Incident', 'Case-Incident', 'Case-Rfi', 'Case-Rft'];

export type TimelineView = 'lanes' | 'list';

const HOUR = 3600 * 1000;
const DAY = 24 * HOUR;
const ZOOM_DURATIONS: Record<Exclude<TimelineZoomWindow, 'fit'>, number> = {
  day: DAY,
  week: 7 * DAY,
  month: 30 * DAY,
  quarter: 91 * DAY,
  year: 365 * DAY,
};
export const TIMELINE_MIN_SPAN = 60 * 1000;
export const TIMELINE_MAX_SPAN = 100 * 365 * DAY;

export type TimelineDomain = [number, number];

export type TimelineSpanUnit = 'minute' | 'hour' | 'day' | 'week' | 'month' | 'year';
export const TIMELINE_SPAN_LABELS: Record<TimelineSpanUnit, string> = {
  minute: '{count, plural, one {# minute} other {# minutes}}',
  hour: '{count, plural, one {# hour} other {# hours}}',
  day: '{count, plural, one {# day} other {# days}}',
  week: '{count, plural, one {# week} other {# weeks}}',
  month: '{count, plural, one {# month} other {# months}}',
  year: '{count, plural, one {# year} other {# years}}',
};

/** The visible span of the lanes in the largest unit that reads naturally ("3 days", "2 weeks"). */
export const describeTimelineSpan = (domain: TimelineDomain): { unit: TimelineSpanUnit; count: number } => {
  const span = Math.max(domain[1] - domain[0], 0);
  if (span < 2 * HOUR) return { unit: 'minute', count: Math.max(1, Math.round(span / (60 * 1000))) };
  if (span < 2 * DAY) return { unit: 'hour', count: Math.round(span / HOUR) };
  if (span < 14 * DAY) return { unit: 'day', count: Math.round(span / DAY) };
  if (span < 60 * DAY) return { unit: 'week', count: Math.round(span / (7 * DAY)) };
  if (span < 730 * DAY) return { unit: 'month', count: Math.round(span / (30 * DAY)) };
  return { unit: 'year', count: Math.round(span / (365 * DAY)) };
};

// region minimal event shape used by the helpers
export interface TimelineEventLike {
  id: string;
  event_time: string;
  event_end_time?: string | null;
  lane: string;
  pinned?: boolean;
  source?: string;
}
// endregion

// region URL view state
export interface TimelineViewState {
  view: TimelineView;
  grouping: TimelineGrouping;
  zoom: TimelineZoomWindow;
  // Visible domain once the user zoomed or panned (null: computed from the zoom window)
  domain: TimelineDomain | null;
  lanes: TimelineLane[];
  kinds: string[];
  sources: TimelineSource[];
  search: string;
  includeHidden: boolean;
  pinnedOnly: boolean;
  event: string | null;
}

export interface TimelineViewDefaults {
  grouping: TimelineGrouping;
  zoom: TimelineZoomWindow;
}

const listParam = <T extends string>(params: URLSearchParams, key: string, allowed: readonly T[]): T[] => {
  const value = params.get(key);
  if (!value) return [];
  return Array.from(new Set(value.split(',').filter((v): v is T => (allowed as readonly string[]).includes(v))));
};

const oneOf = <T extends string>(value: string | null, allowed: readonly T[], fallback: T): T => {
  return value && (allowed as readonly string[]).includes(value) ? value as T : fallback;
};

export const parseTimelineViewState = (params: URLSearchParams, defaults: TimelineViewDefaults): TimelineViewState => {
  const from = Number(params.get('from'));
  const to = Number(params.get('to'));
  const domain: TimelineDomain | null = Number.isFinite(from) && Number.isFinite(to) && from > 0 && to > from ? [from, to] : null;
  return {
    view: oneOf<TimelineView>(params.get('view'), ['lanes', 'list'], 'lanes'),
    grouping: oneOf(params.get('grouping'), TIMELINE_GROUPINGS, defaults.grouping),
    zoom: oneOf(params.get('zoom'), TIMELINE_ZOOM_WINDOWS, defaults.zoom),
    domain,
    lanes: listParam(params, 'lanes', TIMELINE_LANES),
    kinds: listParam(params, 'kinds', TIMELINE_KINDS),
    sources: listParam(params, 'sources', TIMELINE_SOURCES),
    search: params.get('search') ?? '',
    includeHidden: params.get('hidden') === 'true',
    pinnedOnly: params.get('pinned') === 'true',
    event: params.get('event'),
  };
};

/** Serialize the view state, omitting the values equal to the defaults to keep the URL short. */
export const serializeTimelineViewState = (state: TimelineViewState, defaults: TimelineViewDefaults): URLSearchParams => {
  const params = new URLSearchParams();
  if (state.view !== 'lanes') params.set('view', state.view);
  if (state.grouping !== defaults.grouping) params.set('grouping', state.grouping);
  if (state.zoom !== defaults.zoom) params.set('zoom', state.zoom);
  if (state.domain) {
    params.set('from', String(Math.round(state.domain[0])));
    params.set('to', String(Math.round(state.domain[1])));
  }
  if (state.lanes.length > 0) params.set('lanes', state.lanes.join(','));
  if (state.kinds.length > 0) params.set('kinds', state.kinds.join(','));
  if (state.sources.length > 0) params.set('sources', state.sources.join(','));
  if (state.search) params.set('search', state.search);
  if (state.includeHidden) params.set('hidden', 'true');
  if (state.pinnedOnly) params.set('pinned', 'true');
  if (state.event) params.set('event', state.event);
  return params;
};
// endregion

// region time domain
export const toTime = (value: string | Date | null | undefined): number | null => {
  if (!value) return null;
  const time = new Date(value).getTime();
  return Number.isNaN(time) ? null : time;
};

/** Smallest interval containing every event (and its window) and every anchor. */
export const computeTimelineExtent = (events: TimelineEventLike[], anchors: Array<string | null | undefined> = []): TimelineDomain | null => {
  let min = Infinity;
  let max = -Infinity;
  const push = (time: number | null) => {
    if (time === null) return;
    if (time < min) min = time;
    if (time > max) max = time;
  };
  events.forEach((event) => {
    push(toTime(event.event_time));
    push(toTime(event.event_end_time));
  });
  anchors.forEach((anchor) => push(toTime(anchor)));
  if (min === Infinity) return null;
  return [min, max];
};

const clampSpan = (start: number, end: number, focus: number): TimelineDomain => {
  const span = end - start;
  if (span >= TIMELINE_MIN_SPAN && span <= TIMELINE_MAX_SPAN) return [start, end];
  const target = Math.min(Math.max(span, TIMELINE_MIN_SPAN), TIMELINE_MAX_SPAN);
  const ratio = span > 0 ? (focus - start) / span : 0.5;
  const newStart = focus - target * ratio;
  return [newStart, newStart + target];
};

/** Visible domain for a zoom window: the whole extent with a margin, or a window ending on the latest activity. */
export const computeVisibleDomain = (extent: TimelineDomain | null, zoom: TimelineZoomWindow, now = Date.now()): TimelineDomain => {
  const [start, end] = extent ?? [now - 7 * DAY, now];
  if (zoom === 'fit') {
    const span = Math.max(end - start, HOUR);
    const margin = span * 0.04;
    const center = (start + end) / 2;
    return [Math.min(start, center - span / 2) - margin, Math.max(end, center + span / 2) + margin];
  }
  const duration = ZOOM_DURATIONS[zoom];
  if (end - start < duration) {
    const center = (start + end) / 2;
    return [center - duration / 2, center + duration / 2];
  }
  return [end - duration + duration * 0.02, end + duration * 0.02];
};

/**
 * Domain a change of the view (zoom, centering) starts from: the one the user set, else the one the lanes display (the
 * fit of the events), else the zoom window when no lanes are displayed.
 */
export const currentTimelineDomain = (domain: TimelineDomain | null, displayed: TimelineDomain | null, zoom: TimelineZoomWindow): TimelineDomain => {
  return domain ?? displayed ?? computeVisibleDomain(null, zoom);
};

/** Zoom around a focus time: factor < 1 zooms in, factor > 1 zooms out. */
export const zoomDomain = (domain: TimelineDomain, factor: number, focus?: number): TimelineDomain => {
  const [start, end] = domain;
  const center = focus ?? (start + end) / 2;
  const newStart = center - (center - start) * factor;
  const newEnd = center + (end - center) * factor;
  return clampSpan(newStart, newEnd, center);
};

export const panDomain = (domain: TimelineDomain, deltaMs: number): TimelineDomain => [domain[0] + deltaMs, domain[1] + deltaMs];

/** Domain centered on a time, keeping the current span. */
export const centerDomain = (domain: TimelineDomain, time: number): TimelineDomain => {
  const half = (domain[1] - domain[0]) / 2;
  return [time - half, time + half];
};

/**
 * Window of an export: the lanes view exports the window it shows (panned or zoomed, else the zoom window of the events
 * matching the filters); the fit of the lanes and the list view export every event matching the filters.
 */
export const timelineExportWindow = (
  view: TimelineView,
  zoom: TimelineZoomWindow,
  domain: TimelineDomain | null,
  visibleDomain: TimelineDomain | null,
): TimelineDomain | null => {
  if (view !== 'lanes') return null;
  if (domain) return domain;
  if (zoom === 'fit') return null;
  return visibleDomain;
};
// endregion

// region grouping buckets (local time, ISO weeks starting on Monday)
export const bucketStart = (time: number, grouping: TimelineGrouping): number => {
  const date = new Date(time);
  if (grouping === 'hour') {
    date.setMinutes(0, 0, 0);
    return date.getTime();
  }
  date.setHours(0, 0, 0, 0);
  if (grouping === 'week') {
    const dayOfWeek = (date.getDay() + 6) % 7; // Monday = 0
    date.setDate(date.getDate() - dayOfWeek);
  }
  return date.getTime();
};

export const bucketEnd = (start: number, grouping: TimelineGrouping): number => {
  const date = new Date(start);
  if (grouping === 'hour') date.setHours(date.getHours() + 1);
  else if (grouping === 'day') date.setDate(date.getDate() + 1);
  else date.setDate(date.getDate() + 7);
  return date.getTime();
};

export interface TimelineBucket<T> {
  key: number;
  start: number;
  end: number;
  events: T[];
}

/** Group events by the bucket of their start time, in chronological order. */
export const groupEventsByBucket = <T extends TimelineEventLike>(events: T[], grouping: TimelineGrouping): TimelineBucket<T>[] => {
  const buckets = new Map<number, TimelineBucket<T>>();
  events.forEach((event) => {
    const time = toTime(event.event_time);
    if (time === null) return;
    const start = bucketStart(time, grouping);
    const bucket = buckets.get(start) ?? { key: start, start, end: bucketEnd(start, grouping), events: [] };
    bucket.events.push(event);
    buckets.set(start, bucket);
  });
  return Array.from(buckets.values()).sort((a, b) => a.start - b.start);
};

export interface TimelineCluster<T> {
  id: string;
  lane: string;
  start: number;
  end: number;
  events: T[];
}

/**
 * Lanes view items: windows, pinned and manual events are always drawn on their own, the other point
 * events of a lane falling in the same bucket are drawn as one cluster when there are several of them.
 */
export const clusterLaneEvents = <T extends TimelineEventLike>(events: T[], grouping: TimelineGrouping): { singles: T[]; clusters: TimelineCluster<T>[] } => {
  const singles: T[] = [];
  const candidates = new Map<string, TimelineCluster<T>>();
  events.forEach((event) => {
    const time = toTime(event.event_time);
    if (time === null) return;
    const isWindow = !!toTime(event.event_end_time);
    if (isWindow || event.pinned || event.source === 'manual') {
      singles.push(event);
      return;
    }
    const start = bucketStart(time, grouping);
    const key = `${event.lane}|${start}`;
    const cluster = candidates.get(key) ?? { id: `cluster-${key}`, lane: event.lane, start, end: bucketEnd(start, grouping), events: [] };
    cluster.events.push(event);
    candidates.set(key, cluster);
  });
  const clusters: TimelineCluster<T>[] = [];
  candidates.forEach((cluster) => {
    if (cluster.events.length === 1) singles.push(cluster.events[0]);
    else clusters.push(cluster);
  });
  return { singles, clusters };
};
// endregion

// region lane layout
// Approximate width of a character of the 10 px anchor labels, enough to keep two labels apart
const ANCHOR_LABEL_CHAR_WIDTH = 5.5;

export interface AnchorLabelLayout<K extends string = string> {
  key: K;
  x: number;
  label: string;
  row: number;
}

/** Anchor labels kept inside the plot, on successive rows when anchors close in time would make them overlap. */
export const layoutAnchorLabels = <K extends string>(
  anchors: { key: K; x: number; label: string }[],
  plotLeft: number,
  plotRight: number,
): AnchorLabelLayout<K>[] => {
  const placed = anchors.map((anchor) => {
    const halfWidth = (anchor.label.length * ANCHOR_LABEL_CHAR_WIDTH) / 2;
    const x = Math.min(Math.max(anchor.x, plotLeft + halfWidth), Math.max(plotLeft + halfWidth, plotRight - halfWidth));
    return { ...anchor, x, x1: x - halfWidth, x2: x + halfWidth };
  });
  const { rows } = layoutLaneRows(placed.map((anchor) => ({ id: anchor.key, x1: anchor.x1, x2: anchor.x2 })), 8);
  return placed.map(({ key, x, label }) => ({ key, x, label, row: rows.get(key) ?? 0 }));
};

/** Items beyond the rows a lane can draw, in groups of items overlapping on the x axis: each group becomes one count bubble. */
export const groupOverflowItems = <I extends { x1: number; x2: number }>(items: I[], gap = 4): I[][] => {
  const sorted = [...items].sort((a, b) => a.x1 - b.x1 || a.x2 - b.x2);
  const groups: I[][] = [];
  let groupEnd = Number.NEGATIVE_INFINITY;
  sorted.forEach((item) => {
    if (groups.length > 0 && item.x1 <= groupEnd + gap) {
      groups[groups.length - 1].push(item);
      groupEnd = Math.max(groupEnd, item.x2);
    } else {
      groups.push([item]);
      groupEnd = item.x2;
    }
  });
  return groups;
};

export interface LaneLayoutItem {
  id: string;
  x1: number;
  x2: number;
}

/** Greedy interval partitioning: the row of each item so that items of a row never overlap. */
export const layoutLaneRows = (items: LaneLayoutItem[], gap = 4): { rows: Map<string, number>; rowCount: number } => {
  const sorted = [...items].sort((a, b) => a.x1 - b.x1 || a.x2 - b.x2);
  const rowEnds: number[] = [];
  const rows = new Map<string, number>();
  sorted.forEach((item) => {
    let row = rowEnds.findIndex((end) => end + gap <= item.x1);
    if (row < 0) {
      row = rowEnds.length;
      rowEnds.push(item.x2);
    } else {
      rowEnds[row] = item.x2;
    }
    rows.set(item.id, row);
  });
  return { rows, rowCount: Math.max(rowEnds.length, 1) };
};
// endregion

// region exports
export const buildTimelineFileName = (containerName: string, extension: string, date = new Date()): string => {
  const safeName = containerName.replace(/[^\p{L}\p{N}_-]+/gu, '_').replace(/_+/g, '_').replace(/^_|_$/g, '') || 'container';
  const day = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
  return `${safeName}_timeline_${day}.${extension}`;
};

/** Scale the first SVG of an HTML document to a maximum width, keeping its proportions (PDF pages are narrow). */
export const fitSvgToWidth = (html: string, maxWidth: number): string => {
  return html.replace(/<svg([^>]*?)\swidth="(\d+(?:\.\d+)?)"\sheight="(\d+(?:\.\d+)?)"/, (match, before, width, height) => {
    const w = Number(width);
    const h = Number(height);
    if (w <= maxWidth) return match;
    const scaledHeight = Math.round((h * maxWidth) / w);
    return `<svg${before} width="${maxWidth}" height="${scaledHeight}"`;
  });
};
// endregion

// region filters
/** Kinds sent to the API: the explicit selection, else every kind except the ones hidden by the settings. */
export const effectiveKinds = (selected: string[], hiddenKinds: readonly string[]): string[] | null => {
  if (selected.length > 0) return selected;
  if (hiddenKinds.length === 0) return null;
  return TIMELINE_KINDS.filter((kind) => !hiddenKinds.includes(kind));
};

/** Lanes enabled by the settings of the case; no setting yet means every lane. */
export const enabledTimelineLanes = (enabledLanes: readonly string[]): TimelineLane[] => {
  const enabled = TIMELINE_LANES.filter((lane) => enabledLanes.includes(lane));
  return enabled.length > 0 ? enabled : [...TIMELINE_LANES];
};

/**
 * Lanes sent to the API: the selection within the lanes enabled by the settings (a bookmarked selection never shows a
 * lane disabled since), else the enabled lanes; null when every lane applies.
 */
export const effectiveLanes = (selected: readonly string[], enabledLanes: readonly string[]): TimelineLane[] | null => {
  const enabled = enabledTimelineLanes(enabledLanes);
  const chosen = enabled.filter((lane) => selected.includes(lane));
  if (chosen.length > 0) return chosen;
  return enabled.length === TIMELINE_LANES.length ? null : enabled;
};

/**
 * Whether a pin or annotation change can move the event in or out of the loaded events: the filtered list never drops
 * or adds an updated event by itself, so it is read again when the pinned-only view or a search (which matches the
 * annotations) is active.
 */
export const isTimelineViewFilteredBy = (change: 'pin' | 'annotation', state: Pick<TimelineViewState, 'pinnedOnly' | 'search'>): boolean => (
  change === 'pin' ? state.pinnedOnly : state.search.trim().length > 0
);
// endregion

// region compact views (overview card)
// Opening the Timeline tab with this parameter opens the milestone form once (the overview card links to it)
export const TIMELINE_ADD_MILESTONE_PARAM = 'add_milestone';
/** An end time is valid when there is none, or when it comes strictly after the start: a window never ends at its start. */
export const endsAfterStart = (start: Date | null | undefined, end: Date | null | undefined) => (
  !end || !(start instanceof Date) || end.getTime() > start.getTime()
);
// Lane and kind of a new milestone in the milestone form
export const TIMELINE_MILESTONE_DEFAULT_LANE = 'response';
export const TIMELINE_MILESTONE_DEFAULT_KIND = 'milestone';
// Opening the Timeline tab with this parameter opens the settings panel once
export const TIMELINE_OPEN_SETTINGS_PARAM = 'timeline_settings';

/**
 * At most `maxTicks` local midnights inside the domain, evenly stepped by whole days, for a day-precision axis.
 * A domain that holds no midnight gets one tick in its middle, so the day is always named.
 */
export const compactDayTicks = (domain: TimelineDomain, maxTicks = 5): Date[] => {
  const first = new Date(domain[0]);
  first.setHours(0, 0, 0, 0);
  if (first.getTime() < domain[0]) first.setDate(first.getDate() + 1);
  const last = new Date(domain[1]);
  last.setHours(0, 0, 0, 0);
  if (last.getTime() < first.getTime()) return [new Date((domain[0] + domain[1]) / 2)];
  // Rounded: a change of daylight saving time makes a day 23 or 25 hours long
  const days = Math.round((last.getTime() - first.getTime()) / DAY);
  const step = Math.max(1, Math.ceil((days + 1) / maxTicks));
  const ticks: Date[] = [];
  for (let offset = 0; offset <= days && ticks.length < maxTicks; offset += step) {
    const tick = new Date(first);
    tick.setDate(first.getDate() + offset);
    ticks.push(tick);
  }
  return ticks;
};

export interface TimelineElapsed {
  // 1 when the time is after the origin, -1 before, 0 within the same minute
  sign: 1 | -1 | 0;
  days: number;
  hours: number;
  minutes: number;
}

/** Elapsed time between an origin and a time, in whole days, hours and minutes. */
export const elapsedBetween = (origin: number, time: number): TimelineElapsed => {
  const delta = time - origin;
  const totalMinutes = Math.floor(Math.abs(delta) / (60 * 1000));
  if (totalMinutes === 0) return { sign: 0, days: 0, hours: 0, minutes: 0 };
  return {
    sign: delta > 0 ? 1 : -1,
    days: Math.floor(totalMinutes / (24 * 60)),
    hours: Math.floor((totalMinutes % (24 * 60)) / 60),
    minutes: totalMinutes % 60,
  };
};
// endregion

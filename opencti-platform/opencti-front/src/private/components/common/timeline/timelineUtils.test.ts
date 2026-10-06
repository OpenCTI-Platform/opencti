import { describe, expect, it } from 'vitest';
import {
  bucketStart,
  buildTimelineFileName,
  centerDomain,
  clusterLaneEvents,
  compactDayTicks,
  computeTimelineExtent,
  endsAfterStart,
  computeVisibleDomain,
  currentTimelineDomain,
  describeTimelineSpan,
  effectiveKinds,
  effectiveLanes,
  elapsedBetween,
  fitSvgToWidth,
  groupEventsByBucket,
  groupOverflowItems,
  isTimelineViewFilteredBy,
  layoutAnchorLabels,
  layoutLaneRows,
  panDomain,
  parseTimelineViewState,
  serializeTimelineViewState,
  TIMELINE_KINDS,
  TIMELINE_MIN_SPAN,
  type TimelineDomain,
  timelineExportWindow,
  type TimelineViewState,
  zoomDomain,
} from './timelineUtils';

const HOUR = 3600 * 1000;
const DAY = 24 * HOUR;
const DEFAULTS = { grouping: 'day' as const, zoom: 'fit' as const };

// Local noon avoids any day boundary effect of the test machine time zone
const localNoon = (year: number, month: number, day: number) => new Date(year, month - 1, day, 12, 0, 0).getTime();

const event = (id: string, time: number, extra: Record<string, unknown> = {}) => ({
  id,
  event_time: new Date(time).toISOString(),
  lane: 'adversary',
  ...extra,
});

describe('Timeline URL view state', () => {
  it('should parse defaults from an empty query string', () => {
    const state = parseTimelineViewState(new URLSearchParams(''), DEFAULTS);
    expect(state).toEqual({
      view: 'lanes',
      grouping: 'day',
      zoom: 'fit',
      domain: null,
      lanes: [],
      kinds: [],
      sources: [],
      search: '',
      includeHidden: false,
      pinnedOnly: false,
      event: null,
    });
  });

  it('should ignore unknown values and invalid domains', () => {
    const state = parseTimelineViewState(new URLSearchParams('view=gantt&grouping=minute&lanes=adversary,nope,adversary&from=10&to=5&kinds=sighting,unknown'), DEFAULTS);
    expect(state.view).toEqual('lanes');
    expect(state.grouping).toEqual('day');
    expect(state.lanes).toEqual(['adversary']);
    expect(state.kinds).toEqual(['sighting']);
    expect(state.domain).toBeNull();
  });

  it('should round trip a full state and omit the defaults', () => {
    const state: TimelineViewState = {
      view: 'list',
      grouping: 'week',
      zoom: 'month',
      domain: [1000, 5000],
      lanes: ['response', 'detection'],
      kinds: ['containment'],
      sources: ['manual'],
      search: 'isolated',
      includeHidden: true,
      pinnedOnly: true,
      event: 'event-1',
    };
    const params = serializeTimelineViewState(state, DEFAULTS);
    expect(parseTimelineViewState(params, DEFAULTS)).toEqual(state);
    const defaults = serializeTimelineViewState(parseTimelineViewState(new URLSearchParams(''), DEFAULTS), DEFAULTS);
    expect(defaults.toString()).toEqual('');
  });
});

describe('Timeline time domain', () => {
  it('should compute the extent of events, windows and anchors', () => {
    const extent = computeTimelineExtent(
      [event('a', 1000), event('b', 5000, { event_end_time: new Date(9000).toISOString() })],
      [new Date(500).toISOString(), null],
    );
    expect(extent).toEqual([500, 9000]);
    expect(computeTimelineExtent([], [])).toBeNull();
  });

  it('should fit the extent with a margin', () => {
    const [start, end] = computeVisibleDomain([0, 100 * HOUR], 'fit');
    expect(start).toBeLessThan(0);
    expect(end).toBeGreaterThan(100 * HOUR);
  });

  it('should open a zoom window on the latest activity, or centered when the extent is shorter', () => {
    const [start, end] = computeVisibleDomain([0, 100 * DAY], 'week');
    expect(end - start).toEqual(7 * DAY);
    expect(end).toBeGreaterThan(100 * DAY);
    const centered = computeVisibleDomain([0, 2 * HOUR], 'day');
    expect(centered).toEqual([HOUR - DAY / 2, HOUR + DAY / 2]);
  });

  it('should zoom around a focus, pan and center', () => {
    expect(zoomDomain([0, 100 * HOUR], 0.5, 50 * HOUR)).toEqual([25 * HOUR, 75 * HOUR]);
    expect(zoomDomain([0, 100 * HOUR], 2)).toEqual([-50 * HOUR, 150 * HOUR]);
    const zoomed = zoomDomain([0, 10 * HOUR], 0.5, 0);
    expect(zoomed).toEqual([0, 5 * HOUR]);
    expect(panDomain([0, 10], 5)).toEqual([5, 15]);
    expect(centerDomain([0, 10], 100)).toEqual([95, 105]);
  });

  it('should start a zoom or a centering from the domain the user set, else the one the lanes display', () => {
    const displayed: TimelineDomain = [10 * DAY, 40 * DAY];
    expect(currentTimelineDomain([0, HOUR], displayed, 'fit')).toEqual([0, HOUR]);
    // An untouched fit keeps its span: centering on an anchor moves the displayed domain, it does not open a week
    expect(currentTimelineDomain(null, displayed, 'fit')).toEqual(displayed);
    expect(centerDomain(currentTimelineDomain(null, displayed, 'fit'), 30 * DAY)).toEqual([15 * DAY, 45 * DAY]);
    // Without lanes on screen (the list view), the zoom window
    const [start, end] = currentTimelineDomain(null, null, 'week');
    expect(end - start).toEqual(7 * DAY);
  });

  it('should never zoom below one minute', () => {
    const [start, end] = zoomDomain([0, 2 * TIMELINE_MIN_SPAN], 0.01, TIMELINE_MIN_SPAN);
    expect(end - start).toEqual(TIMELINE_MIN_SPAN);
  });

  it('should export the window the lanes show, and every matching event from the fit and the list', () => {
    // Domain of the lanes once filtered, far from the latest event of the whole timeline
    const shown: TimelineDomain = [10 * DAY, 17 * DAY];
    const panned: TimelineDomain = [2 * DAY, 3 * DAY];
    expect(timelineExportWindow('lanes', 'week', null, shown)).toEqual(shown);
    expect(timelineExportWindow('lanes', 'week', panned, shown)).toEqual(panned);
    expect(timelineExportWindow('lanes', 'fit', panned, shown)).toEqual(panned);
    expect(timelineExportWindow('lanes', 'fit', null, shown)).toBeNull();
    expect(timelineExportWindow('list', 'week', panned, shown)).toBeNull();
  });
});

describe('Timeline event window', () => {
  it('accepts a missing end and an end strictly after the start, never an end at or before it', () => {
    const start = new Date('2026-02-05T10:00:00.000Z');
    expect(endsAfterStart(start, null)).toBe(true);
    expect(endsAfterStart(start, new Date('2026-02-05T10:00:01.000Z'))).toBe(true);
    expect(endsAfterStart(start, new Date('2026-02-05T10:00:00.000Z'))).toBe(false);
    expect(endsAfterStart(start, new Date('2026-02-05T09:00:00.000Z'))).toBe(false);
  });
});

describe('Timeline visible span', () => {
  it('should name the span in the largest unit that reads naturally', () => {
    expect(describeTimelineSpan([0, 45 * 60 * 1000])).toEqual({ unit: 'minute', count: 45 });
    expect(describeTimelineSpan([0, 6 * HOUR])).toEqual({ unit: 'hour', count: 6 });
    expect(describeTimelineSpan([0, DAY * 3])).toEqual({ unit: 'day', count: 3 });
    expect(describeTimelineSpan([0, DAY * 21])).toEqual({ unit: 'week', count: 3 });
    expect(describeTimelineSpan([0, DAY * 91])).toEqual({ unit: 'month', count: 3 });
    expect(describeTimelineSpan([0, DAY * 365 * 4])).toEqual({ unit: 'year', count: 4 });
  });

  it('should never name an empty span', () => {
    expect(describeTimelineSpan([10, 10])).toEqual({ unit: 'minute', count: 1 });
  });
});

describe('Timeline grouping', () => {
  it('should bucket by hour, day and ISO week', () => {
    const wednesday = new Date(2026, 1, 4, 15, 42, 10).getTime();
    expect(new Date(bucketStart(wednesday, 'hour'))).toEqual(new Date(2026, 1, 4, 15, 0, 0));
    expect(new Date(bucketStart(wednesday, 'day'))).toEqual(new Date(2026, 1, 4, 0, 0, 0));
    expect(new Date(bucketStart(wednesday, 'week'))).toEqual(new Date(2026, 1, 2, 0, 0, 0));
  });

  it('should group events chronologically', () => {
    const buckets = groupEventsByBucket([
      event('c', localNoon(2026, 2, 5)),
      event('a', localNoon(2026, 2, 3)),
      event('b', localNoon(2026, 2, 3) + HOUR),
    ], 'day');
    expect(buckets.map((b) => b.events.map((e) => e.id))).toEqual([['a', 'b'], ['c']]);
    expect(buckets[0].end - buckets[0].start).toBeGreaterThanOrEqual(23 * HOUR);
  });

  it('should cluster point events of a lane in a bucket, never windows, pinned or manual events', () => {
    const day = localNoon(2026, 2, 3);
    const { singles, clusters } = clusterLaneEvents([
      event('p1', day),
      event('p2', day + HOUR),
      event('other-lane', day, { lane: 'response' }),
      event('window', day, { event_end_time: new Date(day + DAY).toISOString() }),
      event('pinned', day, { pinned: true }),
      event('manual', day, { source: 'manual' }),
    ], 'day');
    expect(clusters).toHaveLength(1);
    expect(clusters[0].events.map((e) => e.id)).toEqual(['p1', 'p2']);
    expect(singles.map((e) => e.id).sort()).toEqual(['manual', 'other-lane', 'pinned', 'window']);
  });
});

describe('Timeline lane layout', () => {
  it('should stack overlapping items on new rows and reuse free rows', () => {
    const { rows, rowCount } = layoutLaneRows([
      { id: 'a', x1: 0, x2: 50 },
      { id: 'b', x1: 10, x2: 20 },
      { id: 'c', x1: 60, x2: 70 },
    ]);
    expect(rows.get('a')).toEqual(0);
    expect(rows.get('b')).toEqual(1);
    expect(rows.get('c')).toEqual(0);
    expect(rowCount).toEqual(2);
    expect(layoutLaneRows([]).rowCount).toEqual(1);
  });
});

describe('Timeline exports', () => {
  it('should build a safe file name', () => {
    expect(buildTimelineFileName('Ransomware / ACME: 2026', 'csv', new Date(2026, 9, 3))).toEqual('Ransomware_ACME_2026_timeline_2026-10-03.csv');
    expect(buildTimelineFileName('***', 'png', new Date(2026, 0, 1))).toEqual('container_timeline_2026-01-01.png');
  });

  it('should scale the first svg of a document to the page width', () => {
    const html = '<div><svg xmlns="http://www.w3.org/2000/svg" width="1200" height="400" viewBox="0 0 1200 400"></svg></div>';
    expect(fitSvgToWidth(html, 600)).toContain('width="600" height="200" viewBox="0 0 1200 400"');
    expect(fitSvgToWidth(html, 1600)).toEqual(html);
  });
});

describe('Timeline filters', () => {
  it('should apply the settings when the user did not select kinds or lanes', () => {
    expect(effectiveKinds(['sighting'], ['sighting'])).toEqual(['sighting']);
    expect(effectiveKinds([], [])).toBeNull();
    const kinds = effectiveKinds([], ['relation_created', 'object_added']);
    expect(kinds).toHaveLength(TIMELINE_KINDS.length - 2);
    expect(kinds).not.toContain('relation_created');
    // A selection outside the enabled lanes (a bookmarked URL) never brings a disabled lane back
    expect(effectiveLanes(['response'], ['adversary'])).toEqual(['adversary']);
    expect(effectiveLanes(['response', 'adversary'], ['adversary', 'detection'])).toEqual(['adversary']);
    expect(effectiveLanes(['response'], [])).toEqual(['response']);
    expect(effectiveLanes([], ['adversary', 'detection', 'response', 'evidence', 'knowledge', 'custom'])).toBeNull();
    expect(effectiveLanes([], ['response', 'adversary'])).toEqual(['adversary', 'response']);
  });

  it('should read the events again after a pin or annotation change only when a filter depends on it', () => {
    // Unpinning in the pinned-only view, or editing an annotation matched by the search, changes what the view lists
    expect(isTimelineViewFilteredBy('pin', { pinnedOnly: true, search: '' })).toBe(true);
    expect(isTimelineViewFilteredBy('annotation', { pinnedOnly: false, search: 'beacon' })).toBe(true);
    // Elsewhere the loaded events stay as they are
    expect(isTimelineViewFilteredBy('pin', { pinnedOnly: false, search: 'beacon' })).toBe(false);
    expect(isTimelineViewFilteredBy('annotation', { pinnedOnly: true, search: '' })).toBe(false);
    // A blank search filters nothing
    expect(isTimelineViewFilteredBy('annotation', { pinnedOnly: false, search: '   ' })).toBe(false);
  });
});

describe('Timeline lane overflow', () => {
  it('should group the overflow items that overlap on the x axis', () => {
    const groups = groupOverflowItems([
      { id: 'c', x1: 300, x2: 320 },
      { id: 'a', x1: 100, x2: 140 },
      { id: 'b', x1: 130, x2: 150 },
      { id: 'd', x1: 322, x2: 330 },
    ]);
    expect(groups.map((group) => group.map((item) => item.id))).toEqual([['a', 'b'], ['c', 'd']]);
  });

  it('should keep apart the items separated by more than the gap', () => {
    const groups = groupOverflowItems([{ id: 'a', x1: 0, x2: 10 }, { id: 'b', x1: 20, x2: 30 }], 4);
    expect(groups).toHaveLength(2);
  });
});

describe('Timeline anchor labels', () => {
  it('should put the labels of close anchors on successive rows', () => {
    const labels = layoutAnchorLabels([
      { key: 'first_adversary_activity', x: 300, label: 'First adversary activity' },
      { key: 'first_detection', x: 320, label: 'First detection' },
      { key: 'closure', x: 900, label: 'Closure' },
    ], 100, 1000);
    const rowOf = (key: string) => labels.find((label) => label.key === key)?.row;
    expect(rowOf('first_adversary_activity')).toEqual(0);
    expect(rowOf('first_detection')).toEqual(1);
    expect(rowOf('closure')).toEqual(0);
  });

  it('should keep a label inside the plot', () => {
    const [left] = layoutAnchorLabels([{ key: 'first_response', x: 101, label: 'First response' }], 100, 1000);
    expect(left.x - ('First response'.length * 5.5) / 2).toBeGreaterThanOrEqual(100);
    const [right] = layoutAnchorLabels([{ key: 'closure', x: 999, label: 'Closure' }], 100, 1000);
    expect(right.x + ('Closure'.length * 5.5) / 2).toBeLessThanOrEqual(1000);
  });
});

describe('Timeline compact views', () => {
  // Local dates: the ticks are local midnights, whatever the time zone of the test machine
  const at = (day: number, hour = 12) => new Date(2026, 1, day, hour, 0, 0, 0).getTime();

  it('steps the day ticks so that at most five fit', () => {
    const ticks = compactDayTicks([at(1, 9), at(20, 9)]);
    expect(ticks.length).toBeLessThanOrEqual(5);
    expect(ticks[0].getTime()).toEqual(new Date(2026, 1, 2).getTime());
    ticks.forEach((tick) => expect([tick.getHours(), tick.getMinutes()]).toEqual([0, 0]));
    const steps = ticks.slice(1).map((tick, index) => Math.round((tick.getTime() - ticks[index].getTime()) / DAY));
    expect(new Set(steps).size).toEqual(1);
  });

  it('gives one tick per day on a short span', () => {
    expect(compactDayTicks([at(1, 9), at(4, 9)]).map((tick) => tick.getDate())).toEqual([2, 3, 4]);
  });

  it('names the day of a span without any midnight', () => {
    const ticks = compactDayTicks([at(3, 8), at(3, 18)]);
    expect(ticks).toHaveLength(1);
    expect(ticks[0].getDate()).toEqual(3);
  });

  it('measures the time elapsed since the first adversary activity', () => {
    expect(elapsedBetween(at(1, 9), at(3, 7) + 30 * 60 * 1000)).toEqual({ sign: 1, days: 1, hours: 22, minutes: 30 });
    expect(elapsedBetween(at(3, 9), at(3, 7))).toEqual({ sign: -1, days: 0, hours: 2, minutes: 0 });
    expect(elapsedBetween(at(3, 9), at(3, 9) + 20 * 1000)).toEqual({ sign: 0, days: 0, hours: 0, minutes: 0 });
  });
});

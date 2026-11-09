import { afterEach, describe, expect, it } from 'vitest';
import moment from 'moment';
import { getServedPublicManifest, resolvePublicDashboardTimeRange, sanitizePublicDashboardUriKey } from '../../../../src/modules/publicDashboard/publicDashboard-utils';
import { ENABLED_FEATURE_FLAGS, TIME_SERIES_BREAKDOWN_FEATURE_FLAG } from '../../../../src/config/conf';
import { fromB64, toB64 } from '../../../../src/utils/base64';

const UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

describe('sanitizePublicDashboardUriKey', () => {
  it('should convert a Latin name to a lowercase hyphenated slug', () => {
    expect(sanitizePublicDashboardUriKey('My Dashboard')).toBe('my-dashboard');
  });

  it('should fall back to a UUID v4 when the input contains only non-Latin characters', () => {
    // Japanese name — all characters are stripped by the ASCII-only regex
    const result = sanitizePublicDashboardUriKey('私のダッシュボード');
    expect(result).toMatch(UUID_V4_REGEX);
  });
});

describe('resolvePublicDashboardTimeRange', () => {
  const requested = { startDate: '2020-01-01T00:00:00.000Z', endDate: '2020-12-31T00:00:00.000Z' };
  const HOUR = 3600 * 1000;
  const iso = (time: number) => new Date(time).toISOString();
  // Clamped to the last day of the destination month, as the resolver computes it
  const monthsBefore = (time: number, months: number) => moment.utc(time).subtract(months, 'months').valueOf();

  it('should honour the range of the visitor when the author allowed viewers to edit the time filters', () => {
    const config = { allowViewersToEditTimeFilters: true, startDate: '2026-01-01T00:00:00.000Z', endDate: null, relativeDate: null };
    expect(resolvePublicDashboardTimeRange(config, requested)).toEqual(requested);
    expect(resolvePublicDashboardTimeRange(config, {})).toEqual({ startDate: undefined, endDate: undefined });
  });

  it('should enforce the absolute range frozen at publication otherwise', () => {
    const config = { startDate: '2026-01-01T00:00:00.000Z', endDate: '2026-03-31T00:00:00.000Z', relativeDate: null };
    expect(resolvePublicDashboardTimeRange(config, requested)).toEqual({ startDate: '2026-01-01T00:00:00.000Z', endDate: '2026-03-31T00:00:00.000Z' });
    // The switch is off by default, and false is not true.
    expect(resolvePublicDashboardTimeRange({ ...config, allowViewersToEditTimeFilters: false }, requested).startDate).toBe('2026-01-01T00:00:00.000Z');
    // One bound outside is enough: the whole published range is used.
    expect(resolvePublicDashboardTimeRange(config, { startDate: '2026-02-01T00:00:00.000Z', endDate: '2026-04-30T00:00:00.000Z' }))
      .toEqual({ startDate: '2026-01-01T00:00:00.000Z', endDate: '2026-03-31T00:00:00.000Z' });
    expect(resolvePublicDashboardTimeRange(config, {})).toEqual({ startDate: '2026-01-01T00:00:00.000Z', endDate: '2026-03-31T00:00:00.000Z' });
  });

  it('should keep the range the public page sends when it lies within the published one', () => {
    const config = { startDate: '2026-01-01T00:00:00.000Z', endDate: '2026-03-31T00:00:00.000Z', relativeDate: null };
    // The page sends the dates of the config as it holds them, in any offset
    const sent = { startDate: '2026-01-01T01:00:00+01:00', endDate: '2026-03-31T00:00:00.000Z' };
    expect(resolvePublicDashboardTimeRange(config, sent)).toEqual(sent);
    const narrower = { startDate: '2026-02-01T00:00:00.000Z', endDate: '2026-02-28T00:00:00.000Z' };
    expect(resolvePublicDashboardTimeRange(config, narrower)).toEqual(narrower);
    // Open on one side: an absent bound stays absent
    const openEnd = { startDate: '2026-01-01T00:00:00.000Z', endDate: null, relativeDate: null };
    expect(resolvePublicDashboardTimeRange(openEnd, { startDate: '2026-06-01T00:00:00.000Z', endDate: null })).toEqual({ startDate: '2026-06-01T00:00:00.000Z', endDate: null });
  });

  it('should compute a relative range frozen at publication back from now', () => {
    const before = Date.now();
    const range = resolvePublicDashboardTimeRange({ relativeDate: 'days-7', startDate: null, endDate: null }, requested);
    const start = new Date(range.startDate as string).getTime();
    const end = new Date(range.endDate as string).getTime();
    expect(end).toBeGreaterThanOrEqual(before);
    expect(end - start).toBeGreaterThanOrEqual(7 * 24 * HOUR - 1000);
    expect(end - start).toBeLessThan(7 * 24 * HOUR + 60 * 1000);
    // An unknown relative date has no start, as in the front, and ends now
    const unknown = resolvePublicDashboardTimeRange({ relativeDate: 'last-week' }, {});
    expect(unknown.startDate).toBeUndefined();
    expect(new Date(unknown.endDate as string).getTime()).toBeGreaterThanOrEqual(before);
  });

  it('should keep the start the public page computes for a relative range, in the time zone of the visitor', () => {
    const now = Date.now();
    // Months and years are counted from the start of the visitor's day: up to one day earlier
    const fromStartOfDay = { startDate: iso(monthsBefore(now, 1) - 20 * HOUR), endDate: iso(now - 1000) };
    expect(resolvePublicDashboardTimeRange({ relativeDate: 'months-1' }, fromStartOfDay)).toEqual(fromStartOfDay);
    const tooEarly = resolvePublicDashboardTimeRange({ relativeDate: 'months-1' }, { startDate: iso(monthsBefore(now, 1) - 30 * HOUR), endDate: iso(now - 1000) });
    expect(new Date(tooEarly.startDate as string).getTime()).toBeGreaterThanOrEqual(monthsBefore(now, 1));
    // Days are counted from now: no more than a daylight saving hour earlier
    const daysSent = { startDate: iso(now - 7 * 24 * HOUR - 30 * 60 * 1000), endDate: iso(now - 1000) };
    expect(resolvePublicDashboardTimeRange({ relativeDate: 'days-7' }, daysSent)).toEqual(daysSent);
    const daysTooEarly = resolvePublicDashboardTimeRange({ relativeDate: 'days-7' }, { startDate: iso(now - 7 * 24 * HOUR - 2 * HOUR), endDate: iso(now - 1000) });
    expect(new Date(daysTooEarly.startDate as string).getTime()).toBeGreaterThanOrEqual(now - 7 * 24 * HOUR);
    // A page left open: its range falls behind, the current one is used, never a shortened one
    const stale = resolvePublicDashboardTimeRange({ relativeDate: 'days-7' }, { startDate: iso(now - 9 * 24 * HOUR), endDate: iso(now - 2 * 24 * HOUR) });
    expect(new Date(stale.endDate as string).getTime()).toBeGreaterThanOrEqual(now);
  });

  it('should honour any range for a dashboard published without range', () => {
    expect(resolvePublicDashboardTimeRange({}, requested)).toEqual(requested);
    expect(resolvePublicDashboardTimeRange(undefined, {})).toEqual({ startDate: undefined, endDate: undefined });
  });
});

describe('getServedPublicManifest', () => {
  const previousEnabledFeatureFlags = [...ENABLED_FEATURE_FLAGS];
  const breakdown = { breakdownBy: 'objectLabel', breakdownLimit: 5, breakdownOrder: 'asc', breakdownOther: true };
  const reports = { mode: 'and', filters: [{ key: ['entity_type'], values: ['Report'], operator: 'eq', mode: 'or' }], filterGroups: [] };
  // The private manifest keeps the filters of the datasets, the public one strips them
  const storedWidgets = {
    'widget-1': {
      type: 'vertical-bar',
      perspective: 'entities',
      dataSelection: [{ perspective: 'entities', filters: reports }],
      parameters: { title: 'Reports', interval: 'week', ...breakdown },
    },
    'widget-2': { type: 'donut', perspective: 'entities', dataSelection: [{ filters: reports }], parameters: { title: 'Donut' } },
    'widget-3': { type: 'text', perspective: null, dataSelection: [] },
  };
  const publicWidgets = {
    'widget-1': { type: 'vertical-bar', perspective: 'entities', dataSelection: [{ perspective: 'entities' }], parameters: { title: 'Reports', interval: 'week', ...breakdown } },
    'widget-2': { type: 'donut', perspective: 'entities', dataSelection: [{}], parameters: { title: 'Donut' } },
    'widget-3': { type: 'text', perspective: null, dataSelection: [] },
  };
  const publicDashboard = (widgets: Record<string, unknown> = storedWidgets, served: Record<string, unknown> = publicWidgets) => ({
    public_manifest: toB64({ widgets: served, config: { refresh_interval: 0 } }) as string,
    private_manifest: toB64({ widgets, config: { refresh_interval: 0 } }) as string,
  });
  const servedWidget = (dashboard: ReturnType<typeof publicDashboard>, widgetId = 'widget-1') => {
    return fromB64(getServedPublicManifest(dashboard) as string).widgets[widgetId];
  };
  const withoutBreakdown = { ...publicWidgets['widget-1'], parameters: { title: 'Reports', interval: 'week' } };

  afterEach(() => {
    ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length, ...previousEnabledFeatureFlags);
  });

  it('should serve the time filters switch only with the dashboard variables feature', () => {
    const served = { 'widget-2': publicWidgets['widget-2'] };
    const dashboard = {
      public_manifest: toB64({ widgets: served, config: { refresh_interval: 0, allowViewersToEditTimeFilters: true } }) as string,
      private_manifest: toB64({ widgets: { 'widget-2': storedWidgets['widget-2'] }, config: { refresh_interval: 0 } }) as string,
    };
    ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length, 'DASHBOARD_VARIABLES');
    expect(getServedPublicManifest(dashboard)).toBe(dashboard.public_manifest);
    ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length);
    expect(fromB64(getServedPublicManifest(dashboard) as string)).toEqual({ widgets: served, config: { refresh_interval: 0 } });
  });

  it('should serve the stored manifest with the time series breakdown flag, its widgets can be broken down', () => {
    ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length, TIME_SERIES_BREAKDOWN_FEATURE_FLAG);
    const dashboard = publicDashboard();
    expect(getServedPublicManifest(dashboard)).toBe(dashboard.public_manifest);
  });

  it('should serve the widgets without their breakdown without the flag, keeping everything else', () => {
    ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length);
    expect(fromB64(getServedPublicManifest(publicDashboard()) as string)).toEqual({
      widgets: { ...publicWidgets, 'widget-1': withoutBreakdown },
      config: { refresh_interval: 0 },
    });
  });

  it('should serve a manifest without breakdown as it is stored, without the flag', () => {
    ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length);
    const dashboard = publicDashboard({ 'widget-2': storedWidgets['widget-2'] }, { 'widget-2': publicWidgets['widget-2'] });
    expect(getServedPublicManifest(dashboard)).toBe(dashboard.public_manifest);
    expect(getServedPublicManifest({ public_manifest: null as unknown as string, private_manifest: dashboard.private_manifest })).toBeNull();
  });

  it('should serve without their breakdown the widgets that cannot be broken down, as the dashboards draw them', () => {
    ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length, TIME_SERIES_BREAKDOWN_FEATURE_FLAG);
    const stored = storedWidgets['widget-1'];
    const [dataset] = stored.dataSelection;
    const drafts = { mode: 'and', filters: [{ key: ['entity_type'], values: ['DraftWorkspace'], operator: 'eq', mode: 'or' }], filterGroups: [] };
    const cannotBreakDown = {
      'not a time series': { ...stored, type: 'donut' },
      'several datasets': { ...stored, dataSelection: [dataset, dataset] },
      'a dataset of another perspective': { ...stored, perspective: 'relationships', dataSelection: [dataset] },
      // only the private manifest tells: the public one has no filters
      'a dataset of draft workspaces': { ...stored, dataSelection: [{ ...dataset, filters: drafts }] },
      'no perspective': { ...stored, perspective: null },
      'an audits line counting distinct values': { ...stored, type: 'line', perspective: 'audits', dataSelection: [{ perspective: 'audits', unique: true }] },
    };
    for (const [rule, widget] of Object.entries(cannotBreakDown)) {
      expect(servedWidget(publicDashboard({ ...storedWidgets, 'widget-1': widget })), rule).toEqual(withoutBreakdown);
    }
    // A widget the private manifest does not hold cannot be broken down either
    expect(servedWidget(publicDashboard({ 'widget-2': storedWidgets['widget-2'] }))).toEqual(withoutBreakdown);
    // The other widgets are served as they are stored
    const dashboard = publicDashboard({ ...storedWidgets, 'widget-1': { ...stored, type: 'donut' } });
    expect(servedWidget(dashboard, 'widget-2')).toEqual(publicWidgets['widget-2']);
    expect(servedWidget(dashboard, 'widget-3')).toEqual(publicWidgets['widget-3']);
  });

  it('should keep the breakdown of every widget that can be broken down', () => {
    ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length, TIME_SERIES_BREAKDOWN_FEATURE_FLAG);
    const stored = storedWidgets['widget-1'];
    const canBreakDown = [
      ...['vertical-bar', 'line', 'area', 'heatmap'].map((type) => ({ ...stored, type })),
      // a dataset without perspective is of the perspective of its widget
      { ...stored, dataSelection: [{ filters: reports }] },
      { ...stored, perspective: 'relationships', dataSelection: [{ perspective: 'relationships' }] },
      // the audits bars count every event, even set to count distinct values
      { ...stored, type: 'vertical-bar', perspective: 'audits', dataSelection: [{ perspective: 'audits', unique: true }] },
    ];
    for (const widget of canBreakDown) {
      const dashboard = publicDashboard({ ...storedWidgets, 'widget-1': widget });
      expect(getServedPublicManifest(dashboard)).toBe(dashboard.public_manifest);
    }
  });
});

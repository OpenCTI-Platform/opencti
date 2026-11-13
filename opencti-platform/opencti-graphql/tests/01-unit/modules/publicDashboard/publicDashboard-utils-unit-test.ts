import { afterEach, describe, expect, it } from 'vitest';
import { getServedPublicManifest, sanitizePublicDashboardUriKey } from '../../../../src/modules/publicDashboard/publicDashboard-utils';
import { ENABLED_FEATURE_FLAGS } from '../../../../src/config/conf';
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

describe('getServedPublicManifest', () => {
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

  const previousEnabledFeatureFlags = [...ENABLED_FEATURE_FLAGS];

  afterEach(() => {
    ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length, ...previousEnabledFeatureFlags);
  });

  it('should never serve the viewer switch of the dashboard: the public time filters stay read only', () => {
    const served = { 'widget-2': publicWidgets['widget-2'] };
    const dashboard = {
      public_manifest: toB64({ widgets: served, config: { refresh_interval: 0, allowViewersToEditTimeFilters: true } }) as string,
      private_manifest: toB64({ widgets: { 'widget-2': storedWidgets['widget-2'] }, config: { refresh_interval: 0 } }) as string,
    };
    expect(fromB64(getServedPublicManifest(dashboard) as string)).toEqual({ widgets: served, config: { refresh_interval: 0 } });
  });

  it('should serve the stored manifest when its widgets can be broken down', () => {
    const dashboard = publicDashboard();
    expect(getServedPublicManifest(dashboard)).toBe(dashboard.public_manifest);
  });

  it('should serve a manifest without breakdown as it is stored', () => {
    const dashboard = publicDashboard({ 'widget-2': storedWidgets['widget-2'] }, { 'widget-2': publicWidgets['widget-2'] });
    expect(getServedPublicManifest(dashboard)).toBe(dashboard.public_manifest);
    expect(getServedPublicManifest({ public_manifest: null as unknown as string, private_manifest: dashboard.private_manifest })).toBeNull();
  });

  it('should serve without their breakdown the widgets that cannot be broken down, as the dashboards draw them', () => {
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

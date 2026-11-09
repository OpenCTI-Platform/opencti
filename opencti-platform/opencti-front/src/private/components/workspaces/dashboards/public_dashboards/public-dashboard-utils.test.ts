import { beforeEach, describe, expect, it } from 'vitest';
import { toB64 } from '../../../../../utils/String';
import { dashboardVariablesStorageKey } from '../../../../../components/dashboard/dashboardVariablesStorage';
import type { DashboardVariable } from '../../../../../components/dashboard/dashboard-types';
import {
  applyPresetToPublishedValues,
  applyPublishedTimeRangeChange,
  buildPublicationInput,
  buildPublishedValuesState,
  buildPublishedVariables,
  buildPublishedVariableValues,
  isSamePublishedTimeRange,
  pickPublishedTimeRange,
} from './public-dashboard-utils';

const USED = '11111111-1111-4111-8111-111111111111';
const UNUSED = '22222222-2222-4222-8222-222222222222';
const SELECTION = '33333333-3333-4333-8333-333333333333';
const VARIABLES: DashboardVariable[] = [
  { id: USED, name: 'Used', type: 'text', restriction: { mode: 'none' }, defaultValue: 'x' },
  { id: UNUSED, name: 'Unused', type: 'text', restriction: { mode: 'none' }, defaultValue: 'u' },
  { id: SELECTION, name: 'Selection', type: 'text', restriction: { mode: 'selection', values: ['a', 'b'] }, defaultValue: 'a' },
];
const tokenWidget = (variableId: string) => ({
  dataSelection: [{ filters: { mode: 'and', filters: [{ key: ['entity_type'], values: [`$var:${variableId}`], operator: 'eq', mode: 'or' }], filterGroups: [] } }],
});
// UNUSED is used by no widget
const WIDGETS = { 'widget-1': tokenWidget(USED), 'widget-2': tokenWidget(SELECTION), 'widget-3': { dataSelection: [{ label: 'no variable' }] } };
const dashboard = (id: string, config = {}) => ({ id, manifest: toB64(JSON.stringify({ widgets: WIDGETS, config, variables: VARIABLES })) });
const formValues = {
  name: 'Public',
  enabled: true,
  uri_key: 'public',
  max_markings: [{ value: 'marking-id', label: 'TLP:GREEN' }],
  dashboard_id: 'dashboard-1',
  variable_values: { [USED]: 'y', [SELECTION]: '' },
  time_range: { relativeDate: 'days-7', startDate: null, endDate: null },
};

describe('buildPublishedVariables', () => {
  it('should only keep the variables used by a widget of the manifest, in the manifest order', () => {
    expect(buildPublishedVariables(VARIABLES, WIDGETS).map((variable) => variable.id)).toEqual([USED, SELECTION]);
    expect(buildPublishedVariables(VARIABLES, undefined)).toEqual([]);
  });
});

describe('buildPublishedVariableValues', () => {
  it('should prefer a valid stored value over the default', () => {
    expect(buildPublishedVariableValues(VARIABLES, { [USED]: 'stored' })).toEqual({ [USED]: 'stored', [UNUSED]: 'u', [SELECTION]: 'a' });
  });

  it('should ignore a stored value outside the selection of the variable', () => {
    expect(buildPublishedVariableValues(VARIABLES, { [SELECTION]: 'c' })[SELECTION]).toEqual('a');
  });
});

describe('buildPublishedValuesState', () => {
  beforeEach(() => window.localStorage.clear());

  it('should start from the values of the selected dashboard only', () => {
    window.localStorage.setItem(dashboardVariablesStorageKey('user-1', 'dashboard-2'), JSON.stringify({ [USED]: 'other dashboard' }));
    expect(buildPublishedValuesState(dashboard('dashboard-1', { relativeDate: 'months-1' }), 'user-1')).toEqual({
      variable_values: { [USED]: 'x', [SELECTION]: 'a' },
      time_range: { relativeDate: 'months-1', startDate: null, endDate: null },
    });
  });

  it('should use the values the user sees on the dashboard', () => {
    window.localStorage.setItem(dashboardVariablesStorageKey('user-1', 'dashboard-1'), JSON.stringify({ [USED]: 'seen' }));
    expect(buildPublishedValuesState(dashboard('dashboard-1'), 'user-1').variable_values[USED]).toEqual('seen');
  });

  it('should be empty without a selected dashboard', () => {
    expect(buildPublishedValuesState(undefined, 'user-1')).toEqual({ variable_values: {}, time_range: { relativeDate: null, startDate: null, endDate: null } });
  });

  it('should prefer the URL values on the page of the dashboard, as the page does', () => {
    window.localStorage.setItem(dashboardVariablesStorageKey('user-1', 'dashboard-1'), JSON.stringify({ [USED]: 'stored' }));
    const search = `?variables=${USED}:url`;
    const onPage = buildPublishedValuesState(dashboard('dashboard-1', { relativeDate: 'months-1' }), 'user-1', search, '/dashboard/workspaces/dashboards/dashboard-1');
    expect(onPage.variable_values[USED]).toEqual('url');
    // The range is the one of the dashboard
    expect(onPage.time_range).toEqual({ relativeDate: 'months-1', startDate: null, endDate: null });
    // From a list, the URL speaks for another dashboard: ignored
    const fromList = buildPublishedValuesState(dashboard('dashboard-1', { relativeDate: 'months-1' }), 'user-1', search, '/dashboard/workspaces/dashboards_public');
    expect(fromList.variable_values[USED]).toEqual('stored');
    // The page of another dashboard whose id starts like this one
    const otherPage = buildPublishedValuesState(dashboard('dashboard-1'), 'user-1', search, '/dashboard/workspaces/dashboards/dashboard-10');
    expect(otherPage.variable_values[USED]).toEqual('stored');
  });
});

describe('applyPublishedTimeRangeChange', () => {
  it('should clear the absolute dates with a relative date', () => {
    expect(applyPublishedTimeRangeChange({ relativeDate: null, startDate: 's', endDate: 'e' }, 'relativeDate', 'days-7'))
      .toEqual({ relativeDate: 'days-7', startDate: null, endDate: null });
  });

  it('should empty a field set to none', () => {
    expect(applyPublishedTimeRangeChange({ relativeDate: 'days-7', startDate: null, endDate: null }, 'relativeDate', 'none'))
      .toEqual({ relativeDate: null, startDate: null, endDate: null });
  });
});

describe('pickPublishedTimeRange', () => {
  it('should read the range of a config, without its other keys', () => {
    expect(pickPublishedTimeRange({ startDate: 's', refresh_interval: 5, allowViewersToEditTimeFilters: true })).toEqual({ startDate: 's', endDate: null, relativeDate: null });
    expect(pickPublishedTimeRange(undefined)).toEqual({ startDate: null, endDate: null, relativeDate: null });
  });

  it('should compare two ranges field by field', () => {
    expect(isSamePublishedTimeRange(pickPublishedTimeRange({ relativeDate: 'days-7' }), { relativeDate: 'days-7', startDate: null, endDate: null })).toBe(true);
    expect(isSamePublishedTimeRange(pickPublishedTimeRange({ relativeDate: 'days-7' }), pickPublishedTimeRange({ relativeDate: 'days-1' }))).toBe(false);
  });
});

describe('buildPublicationInput', () => {
  it('should send the published values, the time range and the time zone', () => {
    const input = buildPublicationInput(formValues, true);
    expect(input.variable_values).toEqual([{ variable_id: USED, value: 'y' }]);
    expect(input.time_range).toEqual({ relative_date: 'days-7', start_date: null, end_date: null });
    expect(input.time_zone).toEqual(Intl.DateTimeFormat().resolvedOptions().timeZone);
    expect(input.allowed_markings_ids).toEqual(['marking-id']);
  });

  it('should send nothing new when the feature flag is disabled', () => {
    const input = buildPublicationInput(formValues, false);
    expect(input).toEqual({ name: 'Public', enabled: true, uri_key: 'public', dashboard_id: 'dashboard-1', allowed_markings_ids: ['marking-id'] });
  });
});

describe('applyPresetToPublishedValues', () => {
  const SECTOR = '11111111-1111-4111-8111-111111111111';
  const REGION = '22222222-2222-4222-8222-222222222222';
  const LEVEL = '33333333-3333-4333-8333-333333333333';
  const variables: DashboardVariable[] = [
    { id: SECTOR, name: 'Sector', type: 'text', restriction: { mode: 'none' }, defaultValue: 'Energy' },
    { id: REGION, name: 'Region', type: 'text', restriction: { mode: 'selection', values: ['eu', 'us'] }, defaultValue: 'eu' },
    { id: LEVEL, name: 'Level', type: 'text', restriction: { mode: 'none' }, defaultValue: 'Low' },
  ];
  const preset = {
    id: 'p1',
    name: 'Finance',
    values: [{ variableId: SECTOR, value: 'Finance' }, { variableId: REGION, value: 'apac' }],
    config: { startDate: null, endDate: null, relativeDate: 'months-1' },
  };

  it('takes the values of the preset, the default for the variables it does not hold or whose value is refused, and its range', () => {
    expect(applyPresetToPublishedValues(preset, variables)).toEqual({
      variable_values: { [SECTOR]: 'Finance', [REGION]: 'eu', [LEVEL]: 'Low' },
      time_range: { startDate: null, endDate: null, relativeDate: 'months-1' },
    });
  });

  it('keeps a value the variable accepts and an absolute range', () => {
    const absolute = { ...preset, values: [{ variableId: REGION, value: 'us' }], config: { startDate: '2026-01-01T00:00:00.000Z', endDate: null, relativeDate: null } };
    expect(applyPresetToPublishedValues(absolute, variables)).toEqual({
      variable_values: { [SECTOR]: 'Energy', [REGION]: 'us', [LEVEL]: 'Low' },
      time_range: { startDate: '2026-01-01T00:00:00.000Z', endDate: null, relativeDate: null },
    });
  });
});

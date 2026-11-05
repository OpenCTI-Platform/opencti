import { beforeEach, describe, expect, it } from 'vitest';
import { toB64 } from '../../../../../utils/String';
import { dashboardTimeRangeStorageKey } from '../../../../../components/dashboard/dashboardTimeRangeStorage';
import { dashboardVariablesStorageKey } from '../../../../../components/dashboard/dashboardVariablesStorage';
import type { DashboardVariable } from '../../../../../components/dashboard/dashboard-types';
import { applyPublishedTimeRangeChange, buildPublicationInput, buildPublishedValuesState, buildPublishedVariables, buildPublishedVariableValues } from './public-dashboard-utils';

const USED = '11111111-1111-4111-8111-111111111111';
const UNUSED = '22222222-2222-4222-8222-222222222222';
const SELECTION = '33333333-3333-4333-8333-333333333333';
const VARIABLES: DashboardVariable[] = [
  { id: USED, name: 'Used', type: 'text', restriction: { mode: 'none' }, defaultValue: 'x' },
  { id: UNUSED, name: 'Unused', type: 'text', restriction: { mode: 'none' }, defaultValue: 'u' },
  { id: SELECTION, name: 'Selection', type: 'text', restriction: { mode: 'selection', values: ['a', 'b'] }, defaultValue: 'a' },
];
const USAGE = [
  { id: USED, usedInWidgetIds: ['widget-1'] },
  { id: UNUSED, usedInWidgetIds: [] },
  { id: SELECTION, usedInWidgetIds: ['widget-2'] },
];
const dashboard = (id: string, config = {}) => ({ id, manifest: toB64(JSON.stringify({ widgets: {}, config, variables: VARIABLES })), variables: USAGE });
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
  it('should only keep the variables used by a widget, in the manifest order', () => {
    expect(buildPublishedVariables(VARIABLES, USAGE).map((variable) => variable.id)).toEqual([USED, SELECTION]);
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

  it('should prefer the URL values and range on the page of the dashboard, as the page does', () => {
    window.localStorage.setItem(dashboardVariablesStorageKey('user-1', 'dashboard-1'), JSON.stringify({ [USED]: 'stored' }));
    const search = `?variables=${USED}:url&timeRange=years-1`;
    const onPage = buildPublishedValuesState(dashboard('dashboard-1', { relativeDate: 'months-1' }), 'user-1', search, '/dashboard/workspaces/dashboards/dashboard-1');
    expect(onPage.variable_values[USED]).toEqual('url');
    expect(onPage.time_range).toEqual({ relativeDate: 'years-1', startDate: null, endDate: null });
    // From a list, the URL speaks for another dashboard: ignored
    const fromList = buildPublishedValuesState(dashboard('dashboard-1', { relativeDate: 'months-1' }), 'user-1', search, '/dashboard/workspaces/dashboards_public');
    expect(fromList.variable_values[USED]).toEqual('stored');
    expect(fromList.time_range).toEqual({ relativeDate: 'months-1', startDate: null, endDate: null });
  });

  it('should start from the range kept in this browser for the dashboard', () => {
    window.localStorage.setItem(dashboardTimeRangeStorageKey('user-1', 'dashboard-1'), JSON.stringify({ relativeDate: 'days-7', startDate: null, endDate: null }));
    expect(buildPublishedValuesState(dashboard('dashboard-1', { relativeDate: 'months-1' }), 'user-1', '', '/x').time_range.relativeDate).toEqual('days-7');
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

describe('buildPublicationInput', () => {
  it('should send the published values, the time range and the time zone', () => {
    const input = buildPublicationInput(formValues);
    expect(input.variable_values).toEqual([{ variable_id: USED, value: 'y' }]);
    expect(input.time_range).toEqual({ relative_date: 'days-7', start_date: null, end_date: null });
    expect(input.time_zone).toEqual(Intl.DateTimeFormat().resolvedOptions().timeZone);
    expect(input.allowed_markings_ids).toEqual(['marking-id']);
  });

});

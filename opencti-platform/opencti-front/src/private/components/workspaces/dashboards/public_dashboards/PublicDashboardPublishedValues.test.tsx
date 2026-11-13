import React from 'react';
import { beforeEach, describe, expect, it } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import { Formik, useFormikContext } from 'formik';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender, { createMockUserContext } from '../../../../../utils/tests/test-render';
import { toB64 } from '../../../../../utils/String';
import { dashboardVariablesStorageKey } from '../../../../../components/dashboard/dashboardVariablesStorage';
import PublicDashboardPublishedValues, { PublicDashboardPublishedValuesLoader } from './PublicDashboardPublishedValues';
import { EMPTY_PUBLISHED_TIME_RANGE, type PublishableDashboard } from './public-dashboard-utils';

const SECTOR = '11111111-1111-4111-8111-111111111111';
const UNUSED = '22222222-2222-4222-8222-222222222222';
const dashboard = (id: string, defaultValue: string): PublishableDashboard => ({
  id,
  manifest: toB64(JSON.stringify({
    widgets: {
      'widget-1': {
        dataSelection: [{ filters: { mode: 'and', filters: [{ key: ['entity_type'], values: [`$var:${SECTOR}`], operator: 'eq', mode: 'or' }], filterGroups: [] } }],
      },
    },
    config: {},
    variables: [
      { id: SECTOR, name: 'Sector name', type: 'text', restriction: { mode: 'none' }, defaultValue },
      { id: UNUSED, name: 'Unused variable', type: 'text', restriction: { mode: 'none' }, defaultValue: 'u' },
    ],
  })),
});

const withPresets = (base: PublishableDashboard): PublishableDashboard => ({
  ...base,
  presets: [{ id: 'p1', name: 'Finance view', values: [{ variableId: SECTOR, value: 'Finance' }], config: { startDate: null, endDate: null, relativeDate: 'months-1' } }],
});

const renderSection = (selected: PublishableDashboard | undefined) => {
  const ui = (current: PublishableDashboard | undefined) => (
    <Formik initialValues={{ variable_values: {}, time_range: EMPTY_PUBLISHED_TIME_RANGE }} onSubmit={() => {}}>
      <PublicDashboardPublishedValues dashboard={current} />
    </Formik>
  );
  const rendered = testRender(ui(selected), { userContext: createMockUserContext({ me: { id: 'user-1', name: 'admin' } }) });
  return { ...rendered, select: (next: PublishableDashboard | undefined) => rendered.rerender(ui(next)) };
};

describe('PublicDashboardPublishedValues', () => {
  beforeEach(() => window.localStorage.clear());

  it('should show nothing without a selected dashboard', () => {
    renderSection(undefined);
    expect(screen.queryByTestId('public-dashboard-published-values')).toBeNull();
  });

  it('should show the time range and the used variables only', () => {
    renderSection(dashboard('dashboard-1', 'Finance'));
    expect(screen.getByText('Published values')).toBeDefined();
    // The date picker labels both its hidden input and its field group: the group is the one to look for
    expect(screen.getByRole('group', { name: 'Start date' })).toBeDefined();
    expect(screen.getByLabelText('Sector name')).toBeDefined();
    expect(screen.queryByLabelText('Unused variable')).toBeNull();
  });

  it('should start from the value the author sees on the dashboard', async () => {
    window.localStorage.setItem(dashboardVariablesStorageKey('user-1', 'dashboard-1'), JSON.stringify({ [SECTOR]: 'Energy' }));
    renderSection(dashboard('dashboard-1', 'Finance'));
    expect(await screen.findByDisplayValue('Energy')).toBeDefined();
  });

  it('should reset the published values when another dashboard is selected', async () => {
    const { user, select } = renderSection(dashboard('dashboard-1', 'Finance'));
    const input = await screen.findByDisplayValue('Finance');
    await user.clear(input);
    await user.type(input, 'Typed');
    select(dashboard('dashboard-2', 'Health'));
    expect(await screen.findByDisplayValue('Health')).toBeDefined();
    expect(screen.queryByDisplayValue('Typed')).toBeNull();
  });

  it('offers to load a preset only when the dashboard holds one, and fills the values and the range from it', async () => {
    renderSection(dashboard('dashboard-1', 'Energy'));
    expect(await screen.findByDisplayValue('Energy')).toBeDefined();
    expect(screen.queryByTestId('public-dashboard-load-preset')).toBeNull();
    const { user } = renderSection(withPresets(dashboard('dashboard-2', 'Energy')));
    const loader = await screen.findByTestId('public-dashboard-load-preset');
    await user.click(within(loader).getByRole('combobox'));
    await user.click(await screen.findByRole('option', { name: 'Finance view' }));
    expect(await screen.findByDisplayValue('Finance')).toBeDefined();
    expect(screen.getByText('Last month')).toBeDefined();
  });
});

// The loader clears the fields as soon as another dashboard is selected, before its data arrives: a submission made
// in between must not carry the values of the previous dashboard with the new id.
describe('PublicDashboardPublishedValuesLoader', () => {
  const Probe = () => {
    const { values } = useFormikContext<{ variable_values: Record<string, string>; time_range: { relativeDate: string | null } }>();
    return <pre data-testid="probe">{JSON.stringify(values)}</pre>;
  };
  const renderLoader = (dashboardId: string) => {
    const ui = (id: string) => (
      <Formik initialValues={{ variable_values: {}, time_range: EMPTY_PUBLISHED_TIME_RANGE }} onSubmit={() => {}}>
        <>
          <PublicDashboardPublishedValuesLoader dashboardId={id} />
          <Probe />
        </>
      </Formik>
    );
    const rendered = testRender(ui(dashboardId), { userContext: createMockUserContext({ me: { id: 'user-1', name: 'admin' } }) });
    const resolve = async (selected: PublishableDashboard) => {
      await waitFor(() => expect(rendered.relayEnv.mock.getAllOperations().length).toBeGreaterThan(0));
      rendered.relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
        Workspace: () => ({ ...selected, variables: [{ id: SECTOR, usedInWidgetIds: ['widget-1'] }, { id: UNUSED, usedInWidgetIds: [] }], presets: [] }),
      }));
    };
    const probe = () => JSON.parse(screen.getByTestId('probe').textContent ?? '{}');
    return { ...rendered, resolve, probe, select: (id: string) => rendered.rerender(ui(id)) };
  };

  it('clears the published values when another dashboard is selected, before its data arrives', async () => {
    const { user, resolve, probe, select } = renderLoader('dashboard-1');
    await resolve(dashboard('dashboard-1', 'Finance'));
    const input = await screen.findByDisplayValue('Finance');
    await user.clear(input);
    await user.type(input, 'Typed');
    expect(probe().variable_values[SECTOR]).toBe('Typed');
    select('dashboard-2');
    await waitFor(() => expect(probe().variable_values).toEqual({}));
    expect(probe().time_range).toEqual(EMPTY_PUBLISHED_TIME_RANGE);
    // The section of the previous dashboard is gone while the next one loads: nothing stale is shown.
    await waitFor(() => expect(screen.queryAllByRole('textbox')).toHaveLength(0));
    await resolve(dashboard('dashboard-2', 'Health'));
    expect(await screen.findByDisplayValue('Health')).toBeDefined();
  });
});

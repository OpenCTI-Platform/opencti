import React from 'react';
import { beforeEach, describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import { Formik } from 'formik';
import testRender, { createMockUserContext } from '../../../../../utils/tests/test-render';
import { toB64 } from '../../../../../utils/String';
import { dashboardVariablesStorageKey } from '../../../../../components/dashboard/dashboardVariablesStorage';
import PublicDashboardPublishedValues from './PublicDashboardPublishedValues';
import { EMPTY_PUBLISHED_TIME_RANGE, type PublishableDashboard } from './public-dashboard-utils';

const SECTOR = '11111111-1111-4111-8111-111111111111';
const UNUSED = '22222222-2222-4222-8222-222222222222';
const dashboard = (id: string, defaultValue: string): PublishableDashboard => ({
  id,
  manifest: toB64(JSON.stringify({
    widgets: {},
    config: {},
    variables: [
      { id: SECTOR, name: 'Sector name', type: 'text', restriction: { mode: 'none' }, defaultValue },
      { id: UNUSED, name: 'Unused variable', type: 'text', restriction: { mode: 'none' }, defaultValue: 'u' },
    ],
  })),
  variables: [{ id: SECTOR, usedInWidgetIds: ['widget-1'] }, { id: UNUSED, usedInWidgetIds: [] }],
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
    expect(screen.getByLabelText('Start date')).toBeDefined();
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
});

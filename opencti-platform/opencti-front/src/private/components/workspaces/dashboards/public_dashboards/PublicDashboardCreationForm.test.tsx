import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen, waitFor } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../../utils/tests/test-render';
import { toB64 } from '../../../../../utils/String';
import PublicDashboardCreationForm from './PublicDashboardCreationForm';

const captured = vi.hoisted(() => ({ commit: vi.fn() }));

vi.mock('../../../../../utils/hooks/useApiMutation', () => ({ default: () => [captured.commit, false] }));
// The marking field loads the markings of the platform: a button picking one stands for it.
vi.mock('@components/common/form/ObjectMarkingField', () => ({
  default: ({ name, setFieldValue }: { name: string; setFieldValue: (field: string, value: unknown) => void }) => (
    <button type="button" onClick={() => setFieldValue(name, [{ value: 'marking-id', label: 'TLP:GREEN' }])}>
      Pick a marking
    </button>
  ),
}));

// The date pickers stand for themselves through two buttons: a date they refuse, then a valid one.
vi.mock('../../../../../components/dashboard/DashboardTimeFilters', () => ({
  default: ({ onInvalidDateChange }: { onInvalidDateChange?: (type: 'startDate' | 'endDate', invalid: boolean) => void }) => (
    <>
      <button type="button" onClick={() => onInvalidDateChange?.('startDate', true)}>Type a refused start date</button>
      <button type="button" onClick={() => onInvalidDateChange?.('startDate', false)}>Fix the start date</button>
    </>
  ),
}));

const SECTOR = '11111111-1111-4111-8111-111111111111';
const MANIFEST = toB64(JSON.stringify({
  widgets: {
    'widget-1': {
      dataSelection: [{ filters: { mode: 'and', filters: [{ key: ['entity_type'], values: [`$var:${SECTOR}`], operator: 'eq', mode: 'or' }], filterGroups: [] } }],
    },
  },
  config: { relativeDate: 'months-1' },
  variables: [{ id: SECTOR, name: 'Sector name', type: 'text', restriction: { mode: 'none' }, defaultValue: 'Finance' }],
}));

const renderForm = (flags: string[]) => {
  const rendered = testRender(<PublicDashboardCreationForm dashboard_id="dashboard-1" />, {
    userContext: createMockUserContext({
      me: { id: 'user-1', name: 'admin' },
      settings: { platform_feature_flags: flags.map((id) => ({ id, enable: true })) },
    }),
  });
  act(() => {
    rendered.relayEnv.mock.resolveMostRecentOperation({
      data: { workspaces: { edges: [{ node: { id: 'dashboard-1', name: 'Dashboard', currentUserAccessRight: 'admin', manifest: MANIFEST } }] } },
    });
  });
  return rendered;
};

const fillAndSubmit = async (user: ReturnType<typeof testRender>['user']) => {
  await user.type(screen.getByLabelText('Name'), 'Finance view');
  await user.click(screen.getByRole('button', { name: 'Pick a marking' }));
  const create = screen.getByRole('button', { name: 'Create' });
  await waitFor(() => expect(create).toBeEnabled());
  await user.click(create);
  await waitFor(() => expect(captured.commit).toHaveBeenCalledTimes(1));
  return captured.commit.mock.calls[0][0].variables.input;
};

describe('PublicDashboardCreationForm', () => {
  beforeEach(() => {
    window.localStorage.clear();
    captured.commit.mockReset();
  });

  it('should publish the values chosen in the published values section, with the time range and the time zone', async () => {
    const { user } = renderForm(['DASHBOARD_VARIABLES']);
    const sector = await screen.findByDisplayValue('Finance');
    await user.clear(sector);
    await user.type(sector, 'Energy');
    const input = await fillAndSubmit(user);
    expect(input).toEqual({
      name: 'Finance view',
      enabled: true,
      uri_key: 'finance-view',
      dashboard_id: 'dashboard-1',
      allowed_markings_ids: ['marking-id'],
      variable_values: [{ variable_id: SECTOR, value: 'Energy' }],
      time_range: { relative_date: 'months-1', start_date: null, end_date: null },
      time_zone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    });
  });

  it('should keep Create disabled while a date picker shows a date it refuses', async () => {
    const { user } = renderForm(['DASHBOARD_VARIABLES']);
    await screen.findByDisplayValue('Finance');
    // The manifest range is relative: the pickers are not in use, a refused date there does not count
    await user.type(screen.getByLabelText('Name'), 'Finance view');
    await user.click(screen.getByRole('button', { name: 'Pick a marking' }));
    const create = screen.getByRole('button', { name: 'Create' });
    await waitFor(() => expect(create).toBeEnabled());
    await user.click(screen.getByRole('button', { name: 'Type a refused start date' }));
    await new Promise((resolve) => {
      setTimeout(resolve, 50);
    });
    expect(create).toBeEnabled();
  });

  it('should block the publication on a refused date when the range is absolute', async () => {
    localStorage.setItem('dashboard-time-range-user-1-dashboard-1', JSON.stringify({ relativeDate: null, startDate: null, endDate: null }));
    const { user } = renderForm(['DASHBOARD_VARIABLES']);
    await screen.findByDisplayValue('Finance');
    await user.type(screen.getByLabelText('Name'), 'Finance view');
    await user.click(screen.getByRole('button', { name: 'Pick a marking' }));
    const create = screen.getByRole('button', { name: 'Create' });
    await waitFor(() => expect(create).toBeEnabled());
    await user.click(screen.getByRole('button', { name: 'Type a refused start date' }));
    await waitFor(() => expect(create).toBeDisabled());
    expect((await screen.findByTestId('public-dashboard-published-date-error')).textContent).toBe('A date of the time range is not valid');
    await user.click(screen.getByRole('button', { name: 'Fix the start date' }));
    await waitFor(() => expect(create).toBeEnabled());
    expect(captured.commit).not.toHaveBeenCalled();
  });

  it('should neither show the section nor send its values without the feature flag', async () => {
    const { user } = renderForm([]);
    await screen.findByLabelText('Name');
    expect(screen.queryByTestId('public-dashboard-published-values')).toBeNull();
    const input = await fillAndSubmit(user);
    expect(input).toEqual({
      name: 'Finance view',
      enabled: true,
      uri_key: 'finance-view',
      dashboard_id: 'dashboard-1',
      allowed_markings_ids: ['marking-id'],
    });
  });
});

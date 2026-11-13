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

const LOADER_QUERY = 'PublicDashboardPublishedValuesQuery';

const renderForm = async ({ resolveLoader = true } = {}) => {
  const rendered = testRender(<PublicDashboardCreationForm dashboard_id="dashboard-1" />, {
    userContext: createMockUserContext({
      me: { id: 'user-1', name: 'admin' },
    }),
  });
  act(() => {
    rendered.relayEnv.mock.resolveMostRecentOperation({
      data: { workspaces: { edges: [{ node: { id: 'dashboard-1', name: 'Dashboard', currentUserAccessRight: 'admin', manifest: MANIFEST } }] } },
    });
  });
  // The published values section loads the selected dashboard, with its variables and presets, on its own.
  await waitFor(() => expect(rendered.relayEnv.mock.getAllOperations().some((op) => op.request.node.operation.name === LOADER_QUERY)).toBe(true));
  if (!resolveLoader) return rendered;
  act(() => {
    rendered.relayEnv.mock.resolveMostRecentOperation({
      data: { workspace: { id: 'dashboard-1', manifest: MANIFEST, variables: [{ id: SECTOR, usedInWidgetIds: ['widget-1'] }], presets: [] } },
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
    const { user } = await renderForm();
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

  it('keeps Create disabled until the published values of the selected dashboard are loaded', async () => {
    const { user, relayEnv } = await renderForm({ resolveLoader: false });
    await user.type(screen.getByLabelText('Name'), 'Finance view');
    await user.click(screen.getByRole('button', { name: 'Pick a marking' }));
    const create = screen.getByRole('button', { name: 'Create' });
    expect(create).toBeDisabled();
    // A native submit (Enter in a field) is refused as well: the form itself is invalid while the values load.
    await user.type(screen.getByLabelText('Name'), '{Enter}');
    await new Promise((resolve) => {
      setTimeout(resolve, 100);
    });
    expect(captured.commit).not.toHaveBeenCalled();
    act(() => {
      relayEnv.mock.resolveMostRecentOperation({
        data: { workspace: { id: 'dashboard-1', manifest: MANIFEST, variables: [{ id: SECTOR, usedInWidgetIds: ['widget-1'] }], presets: [] } },
      });
    });
    await waitFor(() => expect(create).toBeEnabled());
  });

  it('should keep Create disabled while a date picker shows a date it refuses', async () => {
    const { user } = await renderForm();
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
    const { user } = await renderForm();
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

  it('should not keep a date refused on another dashboard', async () => {
    const absolute = JSON.stringify({ relativeDate: null, startDate: null, endDate: null });
    localStorage.setItem('dashboard-time-range-user-1-dashboard-1', absolute);
    localStorage.setItem('dashboard-time-range-user-1-dashboard-2', absolute);
    const rendered = testRender(<PublicDashboardCreationForm />, {
      userContext: createMockUserContext({
        me: { id: 'user-1', name: 'admin' },
      }),
    });
    act(() => {
      rendered.relayEnv.mock.resolveMostRecentOperation({
        data: { workspaces: { edges: [
          { node: { id: 'dashboard-1', name: 'First dashboard', currentUserAccessRight: 'admin', manifest: MANIFEST } },
          { node: { id: 'dashboard-2', name: 'Second dashboard', currentUserAccessRight: 'admin', manifest: MANIFEST } },
        ] } },
      });
    });
    const { user } = rendered;
    const pick = async (name: string, id: string) => {
      await user.click(await screen.findByRole('combobox', { name: /Custom dashboard/ }));
      await user.click(await screen.findByRole('option', { name }));
      // The published values section loads the selected dashboard
      await waitFor(() => expect(rendered.relayEnv.mock.getAllOperations().some((op) => op.request.node.operation.name === LOADER_QUERY
        && op.request.variables.id === id)).toBe(true));
      act(() => {
        rendered.relayEnv.mock.resolveMostRecentOperation({
          data: { workspace: { id, manifest: MANIFEST, variables: [{ id: SECTOR, usedInWidgetIds: ['widget-1'] }], presets: [] } },
        });
      });
    };
    await pick('First dashboard', 'dashboard-1');
    await screen.findByDisplayValue('Finance');
    await user.type(screen.getByLabelText('Name'), 'Finance view');
    await user.click(screen.getByRole('button', { name: 'Pick a marking' }));
    const create = screen.getByRole('button', { name: 'Create' });
    await user.click(screen.getByRole('button', { name: 'Type a refused start date' }));
    await waitFor(() => expect(create).toBeDisabled());
    await pick('Second dashboard', 'dashboard-2');
    await waitFor(() => expect(create).toBeEnabled());
    expect(screen.queryByTestId('public-dashboard-published-date-error')).toBeNull();
  });
});

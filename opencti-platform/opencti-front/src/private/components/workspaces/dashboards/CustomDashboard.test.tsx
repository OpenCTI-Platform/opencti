import React, { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import { toB64 } from '../../../../utils/String';
import { dashboardVariablesStorageKey } from '../../../../components/dashboard/dashboardVariablesStorage';
import CustomDashboard from './CustomDashboard';

const captured = vi.hoisted(() => ({
  values: undefined as ReadonlyMap<string, string> | undefined,
  granted: true,
  commit: vi.fn(),
}));

vi.mock('../../../../components/dashboard/DashboardVariableValuesContext', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../components/dashboard/DashboardVariableValuesContext')>()),
  DashboardVariableValuesProvider: ({ values, children }: { values: ReadonlyMap<string, string>; children: ReactNode }) => {
    captured.values = values;
    return <>{children}</>;
  },
}));

vi.mock('react-relay', async (importOriginal) => ({
  ...(await importOriginal<typeof import('react-relay')>()),
  useFragment: vi.fn((_fragment, data) => data),
}));

vi.mock('../../../../utils/hooks/useApiMutation', () => ({ default: () => [captured.commit, false] }));
vi.mock('../../../../utils/hooks/useGranted', () => ({
  default: () => captured.granted,
  EXPLORE_EXUPDATE: 'EXPLORE_EXUPDATE',
  INVESTIGATION_INUPDATE: 'INVESTIGATION_INUPDATE',
}));
vi.mock('../../../../utils/Security', () => ({
  default: ({ children }: { children: ReactNode }) => <>{children}</>,
}));
vi.mock('../workspaceHeader/WorkspaceHeader', () => ({ default: () => <div>workspace-header</div> }));
vi.mock('../../../../components/dashboard/DashboardTimeFilters', () => ({ default: () => null }));
vi.mock('../../../../components/dashboard/DashboardRefreshControl', () => ({ default: () => null }));
vi.mock('../../../../components/dashboard/DashboardContent', () => ({ default: () => <div>dashboard-content</div> }));

const SECTOR_ID = '11111111-1111-4111-8111-111111111111';
const buildManifest = (config: Record<string, unknown> = {}) => toB64(JSON.stringify({
  widgets: {},
  config,
  variables: [{
    id: SECTOR_ID,
    name: 'Sector',
    type: 'text',
    restriction: { mode: 'none' },
    defaultValue: 'Energy',
  }],
}));
const buildWorkspace = (overrides: Record<string, unknown> = {}, config: Record<string, unknown> = {}) => ({
  id: 'ws-1',
  type: 'dashboard',
  name: 'Dashboard',
  manifest: buildManifest(config),
  refresh_interval: 0,
  currentUserAccessRight: 'admin',
  variables: [{ id: SECTOR_ID, usedInWidgetIds: ['widget-1'] }],
  ...overrides,
});
const workspace = buildWorkspace();

const userContext = (flags: string[]) => createMockUserContext({
  me: { id: 'user-1', name: 'admin' },
  settings: { platform_feature_flags: flags.map((id) => ({ id, enable: true })) },
});

const storeFinanceEverywhere = () => {
  window.localStorage.setItem(
    dashboardVariablesStorageKey('user-1', 'ws-1'),
    JSON.stringify({ [SECTOR_ID]: 'Finance' }),
  );
};

describe('CustomDashboard variable values', () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.history.replaceState(null, '', '/');
    captured.values = undefined;
    captured.granted = true;
  });

  it('feeds the widgets with the per user value when the flag is on', () => {
    storeFinanceEverywhere();
    testRender(
      <CustomDashboard data={workspace as never} />,
      { userContext: userContext(['DASHBOARD_VARIABLES']) },
    );
    expect(screen.getByText('dashboard-content')).toBeInTheDocument();
    expect(captured.values?.get(SECTOR_ID)).toBe('Finance');
  });

  it('reads the manifest defaults only on the home dashboard (noToolbar), whatever localStorage and the URL hold', () => {
    storeFinanceEverywhere();
    const url = `/dashboard?variables=${SECTOR_ID}:Defense`;
    testRender(
      <CustomDashboard data={workspace as never} noToolbar />,
      { userContext: userContext(['DASHBOARD_VARIABLES']), route: url },
    );
    expect(captured.values?.get(SECTOR_ID)).toBe('Energy');
    expect(screen.queryByText('workspace-header')).not.toBeInTheDocument();
    // Neither read nor rewritten.
    expect(window.location.search).toBe(`?variables=${SECTOR_ID}:Defense`);
    expect(window.localStorage.getItem(dashboardVariablesStorageKey('user-1', 'ws-1')))
      .toBe(JSON.stringify({ [SECTOR_ID]: 'Finance' }));
  });

  it('exposes no variable at all when the flag is off', () => {
    storeFinanceEverywhere();
    testRender(<CustomDashboard data={workspace as never} />, { userContext: userContext([]) });
    expect(captured.values?.size).toBe(0);
  });
});

describe('CustomDashboard variables bar', () => {
  const flagOn = () => userContext(['DASHBOARD_VARIABLES']);
  const bar = () => screen.queryByTestId('dashboard-variables-bar');

  beforeEach(() => {
    window.localStorage.clear();
    window.history.replaceState(null, '', '/');
    captured.granted = true;
    captured.commit.mockReset();
    captured.commit.mockImplementation((args) => args.onCompleted?.());
  });

  it('shows the bar to a manager, with a chip per variable and no editing entry point yet', () => {
    testRender(<CustomDashboard data={workspace as never} />, { userContext: flagOn() });
    expect(bar()).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sector : Energy' })).toBeInTheDocument();
    expect(screen.getByTestId('dashboard-variable-chip-Sector')).toHaveAttribute('data-unused', 'false');
    expect(screen.queryByTestId('create-variable-button')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Open menu/ })).not.toBeInTheDocument();
  });

  it('is absent when the feature flag is off', () => {
    testRender(<CustomDashboard data={workspace as never} />, { userContext: userContext([]) });
    expect(bar()).not.toBeInTheDocument();
  });

  it('is absent on the home dashboard (noToolbar)', () => {
    testRender(<CustomDashboard data={workspace as never} noToolbar />, { userContext: flagOn() });
    expect(bar()).not.toBeInTheDocument();
  });

  it('is absent for a reader when viewers are not allowed to change variables', () => {
    captured.granted = false;
    testRender(<CustomDashboard data={buildWorkspace({ currentUserAccessRight: 'view' }) as never} />, { userContext: flagOn() });
    expect(bar()).not.toBeInTheDocument();
  });

  it('is present for a reader when viewers are allowed to change variables, without any action reserved to editors', async () => {
    captured.granted = false;
    const readerWorkspace = buildWorkspace({ currentUserAccessRight: 'view' }, { allowViewersToChangeVariables: true });
    const { user } = testRender(<CustomDashboard data={readerWorkspace as never} />, { userContext: flagOn() });
    expect(bar()).toBeInTheDocument();
    expect(screen.queryByTestId('create-variable-button')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Open menu/ })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Sector : Energy' }));
    await user.tripleClick(screen.getByRole('textbox'));
    await user.paste('Finance');
    expect(captured.values?.get(SECTOR_ID)).toBe('Finance');
    await user.keyboard('{Escape}');
    expect(await screen.findByRole('button', { name: 'Reset' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Set as default values' })).not.toBeInTheDocument();
  });

  it('mutes the chip of a variable no widget uses', () => {
    testRender(<CustomDashboard data={buildWorkspace({ variables: [{ id: SECTOR_ID, usedInWidgetIds: [] }] }) as never} />, { userContext: flagOn() });
    expect(screen.getByTestId('dashboard-variable-chip-Sector')).toHaveAttribute('data-unused', 'true');
  });

  it('resets the values changed locally', async () => {
    storeFinanceEverywhere();
    const { user } = testRender(<CustomDashboard data={workspace as never} />, { userContext: flagOn() });
    expect(screen.getByRole('button', { name: 'Sector : Finance' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Reset' }));
    expect(screen.getByRole('button', { name: 'Sector : Energy' })).toBeInTheDocument();
    expect(captured.values?.get(SECTOR_ID)).toBe('Energy');
  });

  it('sets the local values as the dashboard defaults, then drops the local entry', async () => {
    storeFinanceEverywhere();
    const { user } = testRender(<CustomDashboard data={workspace as never} />, { userContext: flagOn() });
    await user.click(screen.getByRole('button', { name: 'Set as default values' }));
    expect(captured.commit).toHaveBeenCalledTimes(1);
    expect(captured.commit.mock.calls[0][0].variables).toMatchObject({
      id: 'ws-1',
      input: { id: SECTOR_ID, defaultValue: 'Finance' },
    });
    await waitFor(() => expect(window.localStorage.getItem(dashboardVariablesStorageKey('user-1', 'ws-1'))).toBeNull());
  });

  it('keeps the local values when setting the defaults fails, without an unhandled rejection', async () => {
    storeFinanceEverywhere();
    captured.commit.mockImplementation((args) => args.onError?.(new Error('denied')));
    const unhandled = vi.fn();
    process.on('unhandledRejection', unhandled);
    const { user } = testRender(<CustomDashboard data={workspace as never} />, { userContext: flagOn() });
    await user.click(screen.getByRole('button', { name: 'Set as default values' }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Set as default values' })).toBeEnabled());
    await new Promise((resolve) => setTimeout(resolve, 0));
    process.off('unhandledRejection', unhandled);
    expect(unhandled).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Sector : Finance' })).toBeInTheDocument();
  });
});

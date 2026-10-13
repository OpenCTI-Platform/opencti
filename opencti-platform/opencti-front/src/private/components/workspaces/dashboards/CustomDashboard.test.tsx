import React, { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import { toB64 } from '../../../../utils/String';
import { dashboardVariablesStorageKey } from '../../../../components/dashboard/dashboardVariablesStorage';
import CustomDashboard from './CustomDashboard';

const captured = vi.hoisted(() => ({ values: undefined as ReadonlyMap<string, string> | undefined }));

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

vi.mock('../../../../utils/hooks/useApiMutation', () => ({ default: () => [vi.fn()] }));
vi.mock('../../../../utils/hooks/useGranted', () => ({
  default: () => true,
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
const manifest = toB64(JSON.stringify({
  widgets: {},
  config: {},
  variables: [{
    id: SECTOR_ID,
    name: 'Sector',
    type: 'text',
    restriction: { mode: 'none' },
    defaultValue: 'Energy',
  }],
}));
const workspace = {
  id: 'ws-1',
  type: 'dashboard',
  name: 'Dashboard',
  manifest,
  refresh_interval: 0,
  currentUserAccessRight: 'admin',
};

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

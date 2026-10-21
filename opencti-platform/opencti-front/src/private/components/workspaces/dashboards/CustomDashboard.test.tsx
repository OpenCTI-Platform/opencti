import React, { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen, waitFor, within } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import { toB64 } from '../../../../utils/String';
import { dashboardVariablesStorageKey } from '../../../../components/dashboard/dashboardVariablesStorage';
import CustomDashboard from './CustomDashboard';

const captured = vi.hoisted(() => ({
  values: undefined as ReadonlyMap<string, string> | undefined,
  onSetValue: undefined as ((variableId: string, value: string) => void) | undefined,
  contentDefinitions: undefined as { name: string }[] | undefined,
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

// The real bar, which also hands out its way of changing a value: a change that does not come from a chip.
vi.mock('../../../../components/dashboard/variables/DashboardVariablesBar', async (importOriginal) => {
  const Original = (await importOriginal<typeof import('../../../../components/dashboard/variables/DashboardVariablesBar')>()).default;
  return {
    default: (props: React.ComponentProps<typeof Original>) => {
      captured.onSetValue = props.onSetValue;
      return <Original {...props} />;
    },
  };
});

vi.mock('react-relay', async (importOriginal) => ({
  ...(await importOriginal<typeof import('react-relay')>()),
  useFragment: vi.fn((_fragment, data) => data),
}));

vi.mock('../../../../utils/hooks/useApiMutation', () => ({ default: () => [captured.commit, false] }));
// Keep the real capability constants: `*.entries.ts` files read them at import time.
vi.mock('../../../../utils/hooks/useGranted', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../utils/hooks/useGranted')>()),
  default: () => captured.granted,
}));
vi.mock('../../../../utils/Security', () => ({
  default: ({ children }: { children: ReactNode }) => <>{children}</>,
}));
// This module otherwise preloads its query on the application environment at import time.
vi.mock('../../../../utils/hooks/useVocabularyCategory', () => ({ default: vi.fn() }));
// The Create widget entry point lives in the header: it must see the variable definitions too.
vi.mock('../workspaceHeader/WorkspaceHeader', async () => {
  const { useOptionalDashboardVariableDefinitions } = await import('../../../../components/dashboard/DashboardVariablesContext');
  const Header = () => {
    const definitions = useOptionalDashboardVariableDefinitions();
    return (
      <>
        <div>workspace-header</div>
        <div data-testid="header-variable-definitions">{definitions ? definitions.map((v) => v.name).join(',') : 'none'}</div>
      </>
    );
  };
  return { default: Header };
});
vi.mock('../../../../components/dashboard/DashboardTimeFilters', () => ({ default: () => null }));
vi.mock('../../../../components/dashboard/DashboardRefreshControl', () => ({ default: () => null }));
vi.mock('../../../../components/dashboard/DashboardContent', async () => {
  const { useOptionalDashboardVariableDefinitions } = await import('../../../../components/dashboard/DashboardVariablesContext');
  const Content = () => {
    const definitions = useOptionalDashboardVariableDefinitions();
    captured.contentDefinitions = definitions;
    return <div>dashboard-content</div>;
  };
  return { default: Content };
});

const SECTOR_ID = '11111111-1111-4111-8111-111111111111';
const widgetLayout = { w: 4, h: 2, x: 0, y: 0, i: 'x' };
const manifestWidgets = {
  'widget-1': { id: 'widget-1', type: 'list', dataSelection: [], parameters: { title: 'Top malwares' }, layout: widgetLayout },
  'widget-2': { id: 'widget-2', type: 'donut', dataSelection: [], parameters: null, layout: widgetLayout },
};
const buildManifest = (config: Record<string, unknown> = {}) => toB64(JSON.stringify({
  widgets: manifestWidgets,
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

  describe('for a reader (no edit right)', () => {
    const readerWorkspace = (config: Record<string, unknown> = {}) => buildWorkspace({ currentUserAccessRight: 'view' }, config);
    const url = `/dashboard?variables=${SECTOR_ID}:Defense`;

    beforeEach(() => {
      captured.granted = false;
      storeFinanceEverywhere();
    });

    it('ignores, and leaves untouched, the local values when viewers may not change variables', () => {
      testRender(
        <CustomDashboard data={readerWorkspace() as never} />,
        { userContext: userContext(['DASHBOARD_VARIABLES']), route: url },
      );
      expect(captured.values?.get(SECTOR_ID)).toBe('Energy');
      expect(window.location.search).toBe(`?variables=${SECTOR_ID}:Defense`);
      expect(window.localStorage.getItem(dashboardVariablesStorageKey('user-1', 'ws-1')))
        .toBe(JSON.stringify({ [SECTOR_ID]: 'Finance' }));
    });

    it('applies the local values when viewers may change variables', () => {
      testRender(
        <CustomDashboard data={readerWorkspace({ allowViewersToChangeVariables: true }) as never} />,
        { userContext: userContext(['DASHBOARD_VARIABLES']) },
      );
      expect(captured.values?.get(SECTOR_ID)).toBe('Finance');
    });

    it('applies the URL value over the stored one when viewers may change variables', () => {
      testRender(
        <CustomDashboard data={readerWorkspace({ allowViewersToChangeVariables: true }) as never} />,
        { userContext: userContext(['DASHBOARD_VARIABLES']), route: url },
      );
      expect(captured.values?.get(SECTOR_ID)).toBe('Defense');
    });
  });

  it('applies the local values for a manager', () => {
    storeFinanceEverywhere();
    captured.granted = true;
    testRender(<CustomDashboard data={workspace as never} />, { userContext: userContext(['DASHBOARD_VARIABLES']) });
    expect(captured.values?.get(SECTOR_ID)).toBe('Finance');
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

  it('shows the bar to a manager, with a chip per variable and the create, edit and delete entry points', async () => {
    const { user } = testRender(<CustomDashboard data={workspace as never} />, { userContext: flagOn() });
    expect(bar()).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sector : Energy' })).toBeInTheDocument();
    expect(screen.getByTestId('dashboard-variable-chip-Sector')).toHaveAttribute('data-unused', 'false');
    expect(screen.getByTestId('create-variable-button')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Sector : Energy' }));
    expect(screen.getByRole('button', { name: 'Edit variable' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Delete variable' })).toBeInTheDocument();
  });

  const openDeleteDialog = async (user: ReturnType<typeof testRender>['user']) => {
    await user.click(screen.getByRole('button', { name: /^Sector :/ }));
    await user.click(screen.getByRole('button', { name: 'Delete variable' }));
  };

  it('warns about the widgets using the variable by title, falling back to their type', async () => {
    const used = buildWorkspace({ variables: [{ id: SECTOR_ID, usedInWidgetIds: ['widget-1', 'widget-2', 'gone'] }] });
    const { user } = testRender(<CustomDashboard data={used as never} />, { userContext: flagOn() });
    await openDeleteDialog(user);
    const items = within(screen.getByTestId('dashboard-variable-delete-dialog')).getAllByRole('listitem');
    expect(items.map((item) => item.textContent)).toEqual(['Top malwares', 'Donut']);
  });

  it('deletes the variable on confirmation, then closes the dialog', async () => {
    const { user } = testRender(<CustomDashboard data={workspace as never} />, { userContext: flagOn() });
    await openDeleteDialog(user);
    await user.click(screen.getByTestId('dashboard-variable-delete-confirm'));
    expect(captured.commit).toHaveBeenCalledTimes(1);
    expect(captured.commit.mock.calls[0][0].variables).toEqual({ id: 'ws-1', variableId: SECTOR_ID });
    await waitFor(() => expect(screen.queryByTestId('dashboard-variable-delete-dialog')).not.toBeInTheDocument());
  });

  it('deletes nothing when the confirmation is cancelled', async () => {
    const { user } = testRender(<CustomDashboard data={workspace as never} />, { userContext: flagOn() });
    await openDeleteDialog(user);
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(captured.commit).not.toHaveBeenCalled();
    await waitFor(() => expect(screen.queryByTestId('dashboard-variable-delete-dialog')).not.toBeInTheDocument());
  });

  it('keeps the dialog open when the deletion fails', async () => {
    captured.commit.mockImplementation((args) => args.onError?.(new Error('denied')));
    const { user } = testRender(<CustomDashboard data={workspace as never} />, { userContext: flagOn() });
    await openDeleteDialog(user);
    await user.click(screen.getByTestId('dashboard-variable-delete-confirm'));
    await waitFor(() => expect(screen.getByTestId('dashboard-variable-delete-confirm')).toBeEnabled());
    expect(screen.getByTestId('dashboard-variable-delete-dialog')).toBeInTheDocument();
  });

  it('opens the dialog empty from Create variable, then closes it on Cancel', async () => {
    const { user } = testRender(<CustomDashboard data={workspace as never} />, { userContext: flagOn() });
    expect(screen.queryByTestId('dashboard-variable-dialog')).not.toBeInTheDocument();
    await user.click(screen.getByTestId('create-variable-button'));
    expect(screen.getByTestId('dashboard-variable-dialog')).toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: /Name/ })).toHaveValue('');
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByTestId('dashboard-variable-dialog')).not.toBeInTheDocument());
  });

  it('opens the dialog on the variable from its Edit variable entry', async () => {
    const { user } = testRender(<CustomDashboard data={workspace as never} />, { userContext: flagOn() });
    await user.click(screen.getByRole('button', { name: /^Sector :/ }));
    await user.click(screen.getByRole('button', { name: 'Edit variable' }));
    expect(screen.getByTestId('dashboard-variable-dialog')).toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: /Name/ })).toHaveValue('Sector');
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
    await user.click(screen.getByRole('button', { name: 'Sector : Energy' }));
    expect(screen.queryByRole('button', { name: 'Edit variable' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Delete variable' })).not.toBeInTheDocument();
    await user.tripleClick(screen.getByRole('textbox'));
    await user.paste('Finance');
    await user.tab();
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

  it('makes the chips inert while the defaults are being saved', async () => {
    storeFinanceEverywhere();
    let completeMutation: () => void = () => {};
    captured.commit.mockImplementation((args) => {
      completeMutation = () => args.onCompleted?.({});
    });
    const { user } = testRender(<CustomDashboard data={workspace as never} />, { userContext: flagOn() });
    await user.click(screen.getByRole('button', { name: 'Set as default values' }));
    expect(screen.getByRole('button', { name: 'Sector : Finance' })).toBeDisabled();
    act(() => completeMutation());
    await waitFor(() => expect(screen.getByRole('button', { name: 'Sector : Energy' })).toBeEnabled());
  });

  it('keeps a value changed while the defaults are being saved', async () => {
    storeFinanceEverywhere();
    let completeMutation: () => void = () => {};
    captured.commit.mockImplementation((args) => {
      completeMutation = () => args.onCompleted?.({});
    });
    const { user } = testRender(<CustomDashboard data={workspace as never} />, { userContext: flagOn() });
    await user.click(screen.getByRole('button', { name: 'Set as default values' }));
    expect(captured.commit).toHaveBeenCalledTimes(1);
    // Finance is what is being saved: another value is chosen while the request is pending.
    act(() => captured.onSetValue?.(SECTOR_ID, 'Retail'));
    act(() => completeMutation());
    await waitFor(() => expect(screen.getByRole('button', { name: 'Set as default values' })).toBeEnabled());
    expect(screen.getByRole('button', { name: 'Sector : Retail' })).toBeInTheDocument();
    expect(captured.values?.get(SECTOR_ID)).toBe('Retail');
    expect(window.localStorage.getItem(dashboardVariablesStorageKey('user-1', 'ws-1'))).toBe(JSON.stringify({ [SECTOR_ID]: 'Retail' }));
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

describe('CustomDashboard variable definitions for the widget filters', () => {
  const headerDefinitions = () => screen.getByTestId('header-variable-definitions').textContent;

  beforeEach(() => {
    window.localStorage.clear();
    window.history.replaceState(null, '', '/');
    captured.granted = true;
    captured.contentDefinitions = undefined;
  });

  it('provides the definitions to the whole dashboard, header (widget creation) included, when the flag is on', () => {
    testRender(<CustomDashboard data={workspace as never} />, { userContext: userContext(['DASHBOARD_VARIABLES']) });
    expect(headerDefinitions()).toBe('Sector');
    expect(captured.contentDefinitions?.map((v) => v.name)).toEqual(['Sector']);
  });

  it('provides an empty list, still in scope, for a dashboard without variables', () => {
    const noVariables = buildWorkspace({
      manifest: toB64(JSON.stringify({ widgets: manifestWidgets, config: {} })),
      variables: [],
    });
    testRender(<CustomDashboard data={noVariables as never} />, { userContext: userContext(['DASHBOARD_VARIABLES']) });
    expect(headerDefinitions()).toBe('');
    expect(captured.contentDefinitions).toEqual([]);
  });

  it('provides nothing when the flag is off', () => {
    testRender(<CustomDashboard data={workspace as never} />, { userContext: userContext([]) });
    expect(headerDefinitions()).toBe('none');
    expect(captured.contentDefinitions).toBeUndefined();
  });

  it('provides nothing on the home dashboard (noToolbar)', () => {
    testRender(<CustomDashboard data={workspace as never} noToolbar />, { userContext: userContext(['DASHBOARD_VARIABLES']) });
    expect(captured.contentDefinitions).toBeUndefined();
  });
});

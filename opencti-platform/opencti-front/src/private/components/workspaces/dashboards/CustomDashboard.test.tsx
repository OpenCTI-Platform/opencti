import React, { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen, waitFor, within } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import { fromB64, toB64 } from '../../../../utils/String';
import { dashboardVariablesStorageKey } from '../../../../components/dashboard/dashboardVariablesStorage';
import { dashboardTimeRangeStorageKey } from '../../../../components/dashboard/dashboardTimeRangeStorage';
import { MESSAGING$ } from '../../../../relay/environment';
import CustomDashboard from './CustomDashboard';

const captured = vi.hoisted(() => ({
  values: undefined as ReadonlyMap<string, string> | undefined,
  onSetValue: undefined as ((variableId: string, value: string) => void) | undefined,
  contentDefinitions: undefined as { name: string }[] | undefined,
  granted: true,
  commit: vi.fn(),
  relayCommit: vi.fn(),
  timeFilters: undefined as { config: Record<string, unknown>; handleDateChange: (type: 'startDate' | 'endDate' | 'relativeDate', value: string | null) => void } | undefined,
  contentConfig: undefined as Record<string, unknown> | undefined,
  contentMarkerNames: undefined as ReadonlyMap<string, readonly string[]> | undefined,
  handleImportWidget: undefined as ((file: File) => void) | undefined,
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
vi.mock('../../../../utils/hooks/useGranted', () => ({
  default: () => captured.granted,
  EXPLORE_EXUPDATE: 'EXPLORE_EXUPDATE',
  INVESTIGATION_INUPDATE: 'INVESTIGATION_INUPDATE',
}));
vi.mock('../../../../utils/Security', () => ({
  default: ({ children, hasAccess = true }: { children: ReactNode; hasAccess?: boolean }) => (hasAccess ? <>{children}</> : null),
}));
// This module otherwise preloads its query on the application environment at import time.
vi.mock('../../../../utils/hooks/useVocabularyCategory', () => ({ default: vi.fn() }));
// The Create widget entry point lives in the header: it must see the variable definitions too.
vi.mock('../workspaceHeader/WorkspaceHeader', async () => {
  const { useOptionalDashboardVariableDefinitions } = await import('../../../../components/dashboard/DashboardVariablesContext');
  const Header = ({ editionExtra, handleImportWidget }: { editionExtra?: ReactNode; handleImportWidget?: (file: File) => void }) => {
    const definitions = useOptionalDashboardVariableDefinitions();
    captured.handleImportWidget = handleImportWidget;
    return (
      <>
        <div>workspace-header</div>
        <div data-testid="header-variable-definitions">{definitions ? definitions.map((v) => v.name).join(',') : 'none'}</div>
        {editionExtra}
      </>
    );
  };
  return { default: Header };
});
vi.mock('../../../../components/dashboard/DashboardTimeFilters', () => ({
  default: (props: NonNullable<typeof captured.timeFilters>) => {
    captured.timeFilters = props;
    return <div data-testid="time-filters" />;
  },
}));
vi.mock('../../../../components/dashboard/DashboardRefreshControl', () => ({ default: () => <div data-testid="refresh-control" /> }));
vi.mock('../../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../relay/environment')>()),
  commitMutation: (args: unknown) => captured.relayCommit(args),
}));
vi.mock('../../../../components/dashboard/DashboardContent', async () => {
  const { useOptionalDashboardVariableDefinitions } = await import('../../../../components/dashboard/DashboardVariablesContext');
  const Content = ({ helpers, variableNamesByWidget }: { helpers: { config: Record<string, unknown> }; variableNamesByWidget?: ReadonlyMap<string, readonly string[]> }) => {
    const definitions = useOptionalDashboardVariableDefinitions();
    captured.contentDefinitions = definitions;
    captured.contentConfig = helpers.config;
    captured.contentMarkerNames = variableNamesByWidget;
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
  presets: [],
  currentUserDefaultPresetId: null,
  ...overrides,
});
const workspace = buildWorkspace();

const userContext = (flags: string[]) => createMockUserContext({
  me: { id: 'user-1', name: 'admin' },
  settings: { platform_feature_flags: flags.map((id) => ({ id, enable: true })) },
});

type User = ReturnType<typeof testRender>['user'];
// The Save menu of the bar: its trigger, and Set as dashboard defaults inside it.
const saveMenu = () => screen.getByTestId('dashboard-save-menu');
const setAsDefaults = async (user: User) => {
  await user.click(saveMenu());
  await user.click(await screen.findByTestId('dashboard-set-as-defaults'));
};
const pickFinance = async (user: User) => {
  await user.click(screen.getByTestId('dashboard-preset-trigger'));
  await user.click(await screen.findByTestId('dashboard-preset-option-p1'));
};

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

    it('ignores, and leaves untouched, the local values when the editor closed the switches', () => {
      testRender(
        <CustomDashboard data={readerWorkspace({ allowViewersToChangeVariables: false, allowViewersToEditTimeFilters: false }) as never} />,
        { userContext: userContext(['DASHBOARD_VARIABLES']), route: url },
      );
      expect(captured.values?.get(SECTOR_ID)).toBe('Energy');
      expect(window.location.search).toBe(`?variables=${SECTOR_ID}:Defense`);
      expect(window.localStorage.getItem(dashboardVariablesStorageKey('user-1', 'ws-1')))
        .toBe(JSON.stringify({ [SECTOR_ID]: 'Finance' }));
    });

    it('applies the local values by default: a dashboard without the switch lets its viewers change variables', () => {
      testRender(
        <CustomDashboard data={readerWorkspace() as never} />,
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

  it('is absent for a reader when the editor closed the variables switch', () => {
    captured.granted = false;
    testRender(<CustomDashboard data={buildWorkspace({ currentUserAccessRight: 'view' }, { allowViewersToChangeVariables: false }) as never} />, { userContext: flagOn() });
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
    expect(await screen.findByRole('button', { name: 'Reset to defaults' })).toBeInTheDocument();
    expect(screen.queryByTestId('dashboard-save-menu')).not.toBeInTheDocument();
  });

  it('mutes the chip of a variable no widget uses', () => {
    testRender(<CustomDashboard data={buildWorkspace({ variables: [{ id: SECTOR_ID, usedInWidgetIds: [] }] }) as never} />, { userContext: flagOn() });
    expect(screen.getByTestId('dashboard-variable-chip-Sector')).toHaveAttribute('data-unused', 'true');
  });

  it('resets the values changed locally', async () => {
    storeFinanceEverywhere();
    const { user } = testRender(<CustomDashboard data={workspace as never} />, { userContext: flagOn() });
    expect(screen.getByRole('button', { name: 'Sector : Finance' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Reset to defaults' }));
    expect(screen.getByRole('button', { name: 'Sector : Energy' })).toBeInTheDocument();
    expect(captured.values?.get(SECTOR_ID)).toBe('Energy');
  });

  it('sets the local values as the dashboard defaults, then drops the local entry', async () => {
    storeFinanceEverywhere();
    const { user } = testRender(<CustomDashboard data={workspace as never} />, { userContext: flagOn() });
    await setAsDefaults(user);
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
    await setAsDefaults(user);
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
    await setAsDefaults(user);
    expect(captured.commit).toHaveBeenCalledTimes(1);
    // Finance is what is being saved: another value is chosen while the request is pending.
    act(() => captured.onSetValue?.(SECTOR_ID, 'Retail'));
    act(() => completeMutation());
    await waitFor(() => expect(saveMenu()).toBeEnabled());
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
    await setAsDefaults(user);
    await waitFor(() => expect(saveMenu()).toBeEnabled());
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

describe('CustomDashboard time range', () => {
  const flagOn = () => userContext(['DASHBOARD_VARIABLES']);
  const timeRangeKey = dashboardTimeRangeStorageKey('user-1', 'ws-1');
  const relative = (relativeDate: string) => ({ startDate: null, endDate: null, relativeDate });
  const editorWorkspace = buildWorkspace({}, { relativeDate: 'days-7' });
  const changeRange = (relativeDate: string) => act(() => captured.timeFilters?.handleDateChange('relativeDate', relativeDate));

  beforeEach(() => {
    window.localStorage.clear();
    window.history.replaceState(null, '', '/');
    captured.granted = true;
    captured.timeFilters = undefined;
    captured.contentConfig = undefined;
    captured.commit.mockReset();
    captured.commit.mockImplementation((args) => args.onCompleted?.());
    captured.relayCommit.mockReset();
  });

  it('changes the range locally, without any mutation, for an editor', () => {
    testRender(<CustomDashboard data={editorWorkspace as never} />, { userContext: flagOn() });
    changeRange('months-1');
    expect(captured.relayCommit).not.toHaveBeenCalled();
    expect(captured.commit).not.toHaveBeenCalled();
    expect(captured.timeFilters?.config.relativeDate).toBe('months-1');
    expect(captured.contentConfig?.relativeDate).toBe('months-1');
    expect(window.localStorage.getItem(timeRangeKey)).toBe(JSON.stringify(relative('months-1')));
  });

  it('keeps the config given to the widgets across unrelated re-renders, so they do not refetch', async () => {
    const { user } = testRender(<CustomDashboard data={editorWorkspace as never} />, { userContext: flagOn() });
    const before = captured.contentConfig;
    // Opening the variable dialog re-renders the page without changing the range.
    await user.click(screen.getByRole('button', { name: 'Variable' }));
    expect(captured.contentConfig).toBe(before);
  });

  it('places the time filters above the variables bar', () => {
    testRender(<CustomDashboard data={editorWorkspace as never} />, { userContext: flagOn() });
    const filters = screen.getByTestId('time-filters');
    const bar = screen.getByTestId('dashboard-variables-bar');
    expect(filters.compareDocumentPosition(bar) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('applies the URL range on the dashboard page', () => {
    testRender(<CustomDashboard data={editorWorkspace as never} />, { userContext: flagOn(), route: '/dashboard?timeRange=years-1' });
    expect(captured.contentConfig?.relativeDate).toBe('years-1');
  });

  it('reads the manifest range only on the home dashboard', () => {
    window.localStorage.setItem(timeRangeKey, JSON.stringify(relative('months-1')));
    testRender(<CustomDashboard data={editorWorkspace as never} noToolbar />, { userContext: flagOn(), route: '/dashboard?timeRange=years-1' });
    expect(captured.contentConfig?.relativeDate).toBe('days-7');
    expect(screen.queryByTestId('time-filters')).not.toBeInTheDocument();
    expect(window.location.search).toBe('?timeRange=years-1');
    expect(window.localStorage.getItem(timeRangeKey)).toBe(JSON.stringify(relative('months-1')));
  });

  it('shows Reset, Modified and an enabled Set as dashboard defaults in the bar after a date change alone', async () => {
    const { user } = testRender(<CustomDashboard data={editorWorkspace as never} />, { userContext: flagOn() });
    expect(screen.queryByTestId('dashboard-values-reset')).not.toBeInTheDocument();
    expect(screen.queryByTestId('dashboard-values-modified')).not.toBeInTheDocument();
    changeRange('months-1');
    const bar = within(screen.getByTestId('dashboard-variables-bar'));
    expect(bar.getByRole('button', { name: 'Reset to defaults' })).toBeInTheDocument();
    expect(bar.getByTestId('dashboard-values-modified')).toBeInTheDocument();
    await user.click(saveMenu());
    expect(await screen.findByTestId('dashboard-set-as-defaults')).not.toHaveAttribute('data-disabled');
  });

  it('resets both the variables and the range', async () => {
    storeFinanceEverywhere();
    const { user } = testRender(<CustomDashboard data={editorWorkspace as never} />, { userContext: flagOn() });
    changeRange('months-1');
    await user.click(screen.getByRole('button', { name: 'Reset to defaults' }));
    expect(captured.values?.get(SECTOR_ID)).toBe('Energy');
    expect(captured.contentConfig?.relativeDate).toBe('days-7');
    expect(window.localStorage.getItem(timeRangeKey)).toBeNull();
  });

  it('writes the range in manifest.config on Set as dashboard defaults, then drops the local range', async () => {
    const { user } = testRender(<CustomDashboard data={editorWorkspace as never} />, { userContext: flagOn() });
    changeRange('months-1');
    await setAsDefaults(user);
    // Through the mutation hook, which reports every failure: no variable changed, so no other call.
    expect(captured.relayCommit).not.toHaveBeenCalled();
    expect(captured.commit).toHaveBeenCalledTimes(1);
    const [input] = captured.commit.mock.calls[0][0].variables.input;
    expect(input.key).toBe('manifest');
    expect(JSON.parse(fromB64(input.value[0])).config).toMatchObject(relative('months-1'));
    await waitFor(() => expect(window.localStorage.getItem(timeRangeKey)).toBeNull());
  });

  it('keeps the local range and re-enables the chips when Set as dashboard defaults fails', async () => {
    // The hook calls onError on any failure, a network one included.
    captured.commit.mockImplementation((args) => args.onError?.(new Error('Failed to fetch')));
    const { user } = testRender(<CustomDashboard data={editorWorkspace as never} />, { userContext: flagOn() });
    changeRange('months-1');
    await setAsDefaults(user);
    await waitFor(() => expect(saveMenu()).toBeEnabled());
    expect(screen.getByRole('button', { name: 'Sector : Energy' })).toBeEnabled();
    expect(window.localStorage.getItem(timeRangeKey)).toBe(JSON.stringify(relative('months-1')));
    // The range failed: the variables are not sent.
    expect(captured.commit).toHaveBeenCalledTimes(1);
  });

  it('saves the variables first, and does not save the range when a variable is refused', async () => {
    storeFinanceEverywhere();
    // The variable upsert is refused; a manifest write would succeed.
    captured.commit.mockImplementation((args) => (Array.isArray(args.variables.input) ? args.onCompleted?.({}) : args.onError?.(new Error('denied'))));
    const { user } = testRender(<CustomDashboard data={editorWorkspace as never} />, { userContext: flagOn() });
    changeRange('months-1');
    await setAsDefaults(user);
    await waitFor(() => expect(saveMenu()).toBeEnabled());
    expect(captured.commit).toHaveBeenCalledTimes(1);
    expect(captured.commit.mock.calls[0][0].variables.input).toMatchObject({ id: SECTOR_ID, defaultValue: 'Finance' });
    expect(window.localStorage.getItem(timeRangeKey)).toBe(JSON.stringify(relative('months-1')));
  });

  it('keeps a range changed while the defaults are being saved', async () => {
    let completeMutation: () => void = () => {};
    captured.commit.mockImplementation((args) => {
      completeMutation = () => args.onCompleted?.({});
    });
    const { user } = testRender(<CustomDashboard data={editorWorkspace as never} />, { userContext: flagOn() });
    changeRange('months-1');
    await setAsDefaults(user);
    changeRange('years-1');
    act(() => completeMutation());
    await waitFor(() => expect(saveMenu()).toBeEnabled());
    expect(captured.contentConfig?.relativeDate).toBe('years-1');
    expect(window.localStorage.getItem(timeRangeKey)).toBe(JSON.stringify(relative('years-1')));
  });

  describe('for a reader', () => {
    const readerWorkspace = (config: Record<string, unknown> = {}) => buildWorkspace(
      { currentUserAccessRight: 'view' },
      { relativeDate: 'days-7', ...config },
    );

    beforeEach(() => {
      captured.granted = false;
    });

    it('shows no time filter and ignores the URL range when the editor closed the time filters switch', () => {
      testRender(<CustomDashboard data={readerWorkspace({ allowViewersToEditTimeFilters: false }) as never} />, { userContext: flagOn(), route: '/dashboard?timeRange=years-1' });
      expect(screen.queryByTestId('time-filters')).not.toBeInTheDocument();
      expect(captured.contentConfig?.relativeDate).toBe('days-7');
      expect(window.location.search).toBe('?timeRange=years-1');
    });

    it('shows the time filters without the refresh control by default: a dashboard without the switch lets its viewers edit them', () => {
      testRender(<CustomDashboard data={readerWorkspace() as never} />, { userContext: flagOn() });
      expect(screen.getByTestId('time-filters')).toBeInTheDocument();
      expect(screen.queryByTestId('refresh-control')).not.toBeInTheDocument();
      changeRange('months-1');
      expect(captured.contentConfig?.relativeDate).toBe('months-1');
      expect(captured.relayCommit).not.toHaveBeenCalled();
    });

    it('puts Reset at the end of the time filters row when there is no variables bar, never the Save menu', async () => {
      const { user } = testRender(
        <CustomDashboard data={readerWorkspace({ allowViewersToChangeVariables: false }) as never} />,
        { userContext: flagOn() },
      );
      changeRange('months-1');
      expect(screen.queryByTestId('dashboard-variables-bar')).not.toBeInTheDocument();
      expect(screen.queryByTestId('dashboard-save-menu')).not.toBeInTheDocument();
      await user.click(screen.getByRole('button', { name: 'Reset to defaults' }));
      expect(captured.contentConfig?.relativeDate).toBe('days-7');
    });

    it('sees neither the time filters nor the refresh control when the flag is off, whatever the switch holds', () => {
      testRender(
        <CustomDashboard data={readerWorkspace({ allowViewersToEditTimeFilters: true }) as never} />,
        { userContext: userContext([]), route: '/dashboard?timeRange=years-1' },
      );
      expect(screen.queryByTestId('time-filters')).not.toBeInTheDocument();
      expect(screen.queryByTestId('refresh-control')).not.toBeInTheDocument();
      expect(captured.contentConfig?.relativeDate).toBe('days-7');
    });
  });

  it('keeps the current behaviour when the flag is off', () => {
    testRender(<CustomDashboard data={editorWorkspace as never} />, { userContext: userContext([]) });
    expect(screen.getByTestId('refresh-control')).toBeInTheDocument();
    changeRange('months-1');
    expect(captured.commit).toHaveBeenCalledTimes(1);
    expect(captured.commit.mock.calls[0][0].variables.input[0].key).toBe('manifest');
    expect(window.localStorage.getItem(timeRangeKey)).toBeNull();
  });
});

describe('CustomDashboard viewer permissions', () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.history.replaceState(null, '', '/');
    captured.granted = true;
    captured.commit.mockReset();
    captured.relayCommit.mockReset();
  });

  it('gives the edition drawer the viewer permissions when the flag is on', () => {
    testRender(<CustomDashboard data={workspace as never} />, { userContext: userContext(['DASHBOARD_VARIABLES']) });
    expect(screen.getByRole('switch', { name: 'Allow viewers to edit time filters' })).toBeInTheDocument();
    expect(screen.getByRole('switch', { name: 'Allow viewers to change variable values' })).toBeInTheDocument();
  });

  it('gives the edition drawer nothing more when the flag is off', () => {
    testRender(<CustomDashboard data={workspace as never} />, { userContext: userContext([]) });
    expect(screen.queryByRole('switch')).not.toBeInTheDocument();
  });

  it('shows a switch in its new position at once, disabled until it is saved', async () => {
    let completeMutation: () => void = () => {};
    captured.commit.mockImplementation((args) => {
      completeMutation = () => args.onCompleted?.({});
    });
    const { user } = testRender(
      <CustomDashboard data={buildWorkspace({}, { relativeDate: 'days-7' }) as never} />,
      { userContext: userContext(['DASHBOARD_VARIABLES']) },
    );
    const toggle = () => screen.getByRole('switch', { name: 'Allow viewers to edit time filters' });
    // Open by default: the click closes it
    await user.click(toggle());
    expect(toggle()).not.toBeChecked();
    expect(toggle()).toBeDisabled();
    act(() => completeMutation());
    await waitFor(() => expect(toggle()).toBeEnabled());
  });

  it('saves a switch through the dashboard config, keeping the other keys', async () => {
    const { user } = testRender(
      <CustomDashboard data={buildWorkspace({}, { relativeDate: 'days-7' }) as never} />,
      { userContext: userContext(['DASHBOARD_VARIABLES']) },
    );
    await user.click(screen.getByRole('switch', { name: 'Allow viewers to change variable values' }));
    expect(captured.commit).toHaveBeenCalledTimes(1);
    const [input] = captured.commit.mock.calls[0][0].variables.input;
    expect(input.key).toBe('manifest');
    expect(JSON.parse(fromB64(input.value[0])).config).toStrictEqual({ relativeDate: 'days-7', allowViewersToChangeVariables: false });
  });
});

describe('CustomDashboard widget usage marker', () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.history.replaceState(null, '', '/');
    captured.contentMarkerNames = undefined;
  });

  it('gives the widgets the names of the variables they use, from the server usage, to readers too', () => {
    captured.granted = false;
    testRender(
      <CustomDashboard data={buildWorkspace({ currentUserAccessRight: 'view' }) as never} />,
      { userContext: userContext(['DASHBOARD_VARIABLES']) },
    );
    expect([...(captured.contentMarkerNames ?? [])]).toEqual([['widget-1', ['Sector']]]);
    captured.granted = true;
  });

  it('gives no marker on the home dashboard', () => {
    testRender(<CustomDashboard data={workspace as never} noToolbar />, { userContext: userContext(['DASHBOARD_VARIABLES']) });
    expect(captured.contentMarkerNames).toBeUndefined();
  });

  it('gives no marker when the flag is off', () => {
    testRender(<CustomDashboard data={workspace as never} />, { userContext: userContext([]) });
    expect(captured.contentMarkerNames).toBeUndefined();
  });
});

describe('CustomDashboard widget import', () => {
  const MISSING_ID = '22222222-2222-4222-8222-222222222222';
  const tokenFilters = (ids: string[]) => ({ mode: 'and', filters: [{ key: ['entity_type'], values: ids.map((id) => `$var:${id}`), operator: 'eq', mode: 'or' }], filterGroups: [] });
  const widgetFile = (ids: string[]) => new File([JSON.stringify({
    openCTI_version: '7.0.0',
    type: 'widget',
    configuration: toB64(JSON.stringify({ type: 'number', perspective: 'entities', dataSelection: [{ filters: tokenFilters(ids) }] })),
  })], 'widget.json', { type: 'application/json' });
  const widgetImportCall = () => captured.commit.mock.calls.find(([config]) => config?.variables?.input?.importType === 'widget')?.[0];

  beforeEach(() => {
    window.localStorage.clear();
    window.history.replaceState(null, '', '/');
    captured.granted = true;
    captured.commit.mockReset();
    captured.handleImportWidget = undefined;
  });

  it('warns about the variables of the imported widget missing from the dashboard, once imported', async () => {
    const notifyWarning = vi.spyOn(MESSAGING$, 'notifyWarning');
    testRender(<CustomDashboard data={workspace as never} />, { userContext: userContext(['DASHBOARD_VARIABLES']) });
    act(() => captured.handleImportWidget?.(widgetFile([SECTOR_ID, MISSING_ID])));
    await waitFor(() => expect(widgetImportCall()).toBeDefined());
    expect(notifyWarning).not.toHaveBeenCalled();
    act(() => widgetImportCall().onCompleted());
    expect(notifyWarning).toHaveBeenCalledTimes(1);
    // One variable of the two is missing: the message carries that count
    expect(notifyWarning.mock.calls[0][0]).toContain('uses 1 variable');
    notifyWarning.mockRestore();
  });

  it('warns about nothing when the dashboard holds every variable of the widget, or without the feature flag', async () => {
    const notifyWarning = vi.spyOn(MESSAGING$, 'notifyWarning');
    const { unmount } = testRender(<CustomDashboard data={workspace as never} />, { userContext: userContext(['DASHBOARD_VARIABLES']) });
    act(() => captured.handleImportWidget?.(widgetFile([SECTOR_ID])));
    await waitFor(() => expect(widgetImportCall()).toBeDefined());
    act(() => widgetImportCall().onCompleted());
    unmount();
    captured.commit.mockReset();
    testRender(<CustomDashboard data={workspace as never} />, { userContext: userContext([]) });
    act(() => captured.handleImportWidget?.(widgetFile([MISSING_ID])));
    await waitFor(() => expect(widgetImportCall()).toBeDefined());
    act(() => widgetImportCall().onCompleted());
    expect(notifyWarning).not.toHaveBeenCalled();
    notifyWarning.mockRestore();
  });

  it('still imports the widget when the file cannot be read', async () => {
    testRender(<CustomDashboard data={workspace as never} />, { userContext: userContext(['DASHBOARD_VARIABLES']) });
    const unreadable = widgetFile([MISSING_ID]);
    vi.spyOn(unreadable, 'text').mockRejectedValue(new Error('The file was removed'));
    act(() => captured.handleImportWidget?.(unreadable));
    await waitFor(() => expect(widgetImportCall()).toBeDefined());
    expect(widgetImportCall().variables.input.file).toBe(unreadable);
  });
});

describe('CustomDashboard presets', () => {
  const flagOn = () => userContext(['DASHBOARD_VARIABLES']);
  const finance = { id: 'p1', name: 'Finance', values: [{ variableId: SECTOR_ID, value: 'Finance' }], config: { startDate: null, endDate: null, relativeDate: 'months-1' } };
  const withPresets = (overrides: Record<string, unknown> = {}, config: Record<string, unknown> = {}) => buildWorkspace({ presets: [finance], ...overrides }, { relativeDate: 'days-7', ...config });
  const selector = () => screen.queryByTestId('dashboard-preset-selector');

  beforeEach(() => {
    window.localStorage.clear();
    window.history.replaceState(null, '', '/');
    captured.granted = true;
    captured.commit.mockReset();
  });

  it('applies the values and the range of the preset picked by an editor, and Reset puts the defaults back', async () => {
    const { user } = testRender(<CustomDashboard data={withPresets() as never} />, { userContext: flagOn() });
    await pickFinance(user);
    expect(captured.values?.get(SECTOR_ID)).toBe('Finance');
    expect(captured.contentConfig?.relativeDate).toBe('months-1');
    expect(new URLSearchParams(window.location.search).get('preset')).toBe('p1');
    await user.click(within(screen.getByTestId('dashboard-variables-bar')).getByRole('button', { name: 'Reset to defaults' }));
    expect(captured.values?.get(SECTOR_ID)).toBe('Energy');
    expect(captured.contentConfig?.relativeDate).toBe('days-7');
    expect(new URLSearchParams(window.location.search).get('preset')).toBeNull();
  });

  it('lets a viewer who may only switch presets apply one, on its own row, without any editor action', async () => {
    captured.granted = false;
    const viewer = withPresets({ currentUserAccessRight: 'view' }, { allowViewersToChangeVariables: false, allowViewersToEditTimeFilters: false });
    const { user } = testRender(<CustomDashboard data={viewer as never} />, { userContext: flagOn() });
    expect(selector()).toBeInTheDocument();
    expect(screen.queryByTestId('dashboard-variables-bar')).not.toBeInTheDocument();
    expect(screen.queryByTestId('dashboard-save-menu')).not.toBeInTheDocument();
    await pickFinance(user);
    expect(captured.values?.get(SECTOR_ID)).toBe('Finance');
    expect(captured.contentConfig?.relativeDate).toBe('months-1');
  });

  it('hides the selector from a viewer when the editor closed the presets switch, even with presets', () => {
    captured.granted = false;
    testRender(<CustomDashboard data={withPresets({ currentUserAccessRight: 'view' }, { allowViewersToSwitchPresets: false }) as never} />, { userContext: flagOn() });
    expect(selector()).not.toBeInTheDocument();
    expect(captured.values?.get(SECTOR_ID)).toBe('Energy');
  });

  it('opens on the default preset of the user, marks it, and Reset goes back to it rather than to the manifest', async () => {
    const { user } = testRender(<CustomDashboard data={withPresets({ currentUserDefaultPresetId: 'p1' }) as never} />, { userContext: flagOn() });
    expect(captured.values?.get(SECTOR_ID)).toBe('Finance');
    expect(captured.contentConfig?.relativeDate).toBe('months-1');
    expect(screen.getByTestId('dashboard-preset-trigger')).toHaveTextContent('Finance');
    await user.click(screen.getByTestId('dashboard-preset-trigger'));
    expect(await screen.findByTestId('dashboard-preset-option-p1')).toHaveTextContent('FinanceDefault');
    await user.keyboard('{Escape}');
    act(() => captured.onSetValue?.(SECTOR_ID, 'Retail'));
    expect(captured.values?.get(SECTOR_ID)).toBe('Retail');
    await user.click(within(screen.getByTestId('dashboard-variables-bar')).getByRole('button', { name: 'Reset to “Finance”' }));
    expect(captured.values?.get(SECTOR_ID)).toBe('Finance');
  });

  it('opens on the preset of the URL alone, values and range included, as a shared address', () => {
    window.history.replaceState(null, '', '/?preset=p1');
    testRender(<CustomDashboard data={withPresets() as never} />, { userContext: flagOn() });
    expect(screen.getByTestId('dashboard-preset-trigger')).toHaveTextContent('Finance');
    expect(captured.values?.get(SECTOR_ID)).toBe('Finance');
    expect(captured.contentConfig?.relativeDate).toBe('months-1');
  });

  it('keeps the per user changes apart from the preset, and enables its update only once a value differs', async () => {
    const { user } = testRender(<CustomDashboard data={withPresets() as never} />, { userContext: flagOn() });
    await pickFinance(user);
    expect(screen.queryByTestId('dashboard-values-modified')).not.toBeInTheDocument();
    await user.click(saveMenu());
    expect(await screen.findByTestId('dashboard-preset-update')).toHaveAttribute('data-disabled');
    act(() => captured.onSetValue?.(SECTOR_ID, 'Retail'));
    expect(captured.values?.get(SECTOR_ID)).toBe('Retail');
    expect(screen.getByTestId('dashboard-preset-update')).not.toHaveAttribute('data-disabled');
    expect(screen.getByTestId('dashboard-values-modified')).toBeInTheDocument();
    expect(new URLSearchParams(window.location.search).get('variables')).toBe(`${SECTOR_ID}:Retail`);
  });

  it('ignores the URL values and range for a viewer who may only switch presets', () => {
    captured.granted = false;
    window.history.replaceState(null, '', `/?preset=p1&variables=${SECTOR_ID}:Retail&timeRange=days-30`);
    storeFinanceEverywhere();
    const viewer = withPresets({ currentUserAccessRight: 'view' }, { allowViewersToChangeVariables: false, allowViewersToEditTimeFilters: false });
    testRender(<CustomDashboard data={viewer as never} />, { userContext: flagOn() });
    expect(captured.values?.get(SECTOR_ID)).toBe('Finance');
    expect(captured.contentConfig?.relativeDate).toBe('months-1');
  });

  it('writes the range of the active preset in the manifest on Set as dashboard defaults', async () => {
    captured.commit.mockImplementation((args) => args.onCompleted?.({}));
    const { user } = testRender(<CustomDashboard data={withPresets() as never} />, { userContext: flagOn() });
    await pickFinance(user);
    await setAsDefaults(user);
    const manifestCall = captured.commit.mock.calls.map((call) => call[0].variables.input).flat().find((input) => input.key === 'manifest');
    expect(manifestCall).toBeDefined();
    expect(JSON.parse(fromB64(manifestCall.value[0])).config).toMatchObject({ relativeDate: 'months-1' });
  });

  it('drops the values and the range of the active preset when it is deleted', async () => {
    captured.commit.mockImplementation((args) => args.onCompleted?.({}));
    const { user } = testRender(<CustomDashboard data={withPresets() as never} />, { userContext: flagOn() });
    await pickFinance(user);
    expect(captured.values?.get(SECTOR_ID)).toBe('Finance');
    await user.click(screen.getByTestId('dashboard-preset-trigger'));
    await user.click(await screen.findByTestId('dashboard-preset-delete'));
    await user.click(await screen.findByTestId('dashboard-preset-delete-confirm'));
    expect(captured.commit).toHaveBeenCalledWith(expect.objectContaining({ variables: { id: 'ws-1', presetId: 'p1' } }));
    expect(captured.values?.get(SECTOR_ID)).toBe('Energy');
    expect(captured.contentConfig?.relativeDate).toBe('days-7');
    expect(new URLSearchParams(window.location.search).get('preset')).toBeNull();
  });

  it('falls back to the manifest default, not to the default preset of the user, for a variable the picked preset does not hold', async () => {
    const LEVEL_ID = '33333333-3333-4333-8333-333333333333';
    const manifest = toB64(JSON.stringify({
      widgets: manifestWidgets,
      config: { relativeDate: 'days-7' },
      variables: [
        { id: SECTOR_ID, name: 'Sector', type: 'text', restriction: { mode: 'none' }, defaultValue: 'Energy' },
        { id: LEVEL_ID, name: 'Level', type: 'text', restriction: { mode: 'none' }, defaultValue: 'Low' },
      ],
    }));
    const healthcare = { id: 'p2', name: 'Healthcare', values: [{ variableId: SECTOR_ID, value: 'Healthcare' }, { variableId: LEVEL_ID, value: 'High' }], config: { startDate: null, endDate: null, relativeDate: 'days-7' } };
    const data = buildWorkspace({
      manifest,
      variables: [{ id: SECTOR_ID, usedInWidgetIds: ['widget-1'] }, { id: LEVEL_ID, usedInWidgetIds: ['widget-1'] }],
      presets: [finance, healthcare],
      currentUserDefaultPresetId: 'p2',
    });
    const { user } = testRender(<CustomDashboard data={data as never} />, { userContext: flagOn() });
    expect(captured.values?.get(LEVEL_ID)).toBe('High');
    await pickFinance(user);
    expect(captured.values?.get(SECTOR_ID)).toBe('Finance');
    expect(captured.values?.get(LEVEL_ID)).toBe('Low');
    await user.click(saveMenu());
    expect(await screen.findByTestId('dashboard-preset-update')).toHaveAttribute('data-disabled');
  });

  it('shows no selector and applies no preset, not even the default one or the one of the URL, when the flag is off', () => {
    window.history.replaceState(null, '', '/?preset=p1');
    testRender(<CustomDashboard data={withPresets({ currentUserDefaultPresetId: 'p1' }) as never} />, { userContext: userContext([]) });
    expect(selector()).not.toBeInTheDocument();
    // No variable value at all is provided without the flag, and the range is the one of the manifest
    expect(captured.values?.size ?? 0).toBe(0);
    expect(captured.contentConfig?.relativeDate).toBe('days-7');
  });

  it('applies the default preset on the home dashboard without selector nor local read', () => {
    storeFinanceEverywhere();
    window.localStorage.setItem(dashboardVariablesStorageKey('user-1', 'ws-1'), JSON.stringify({ [SECTOR_ID]: 'Retail' }));
    testRender(<CustomDashboard data={withPresets({ currentUserDefaultPresetId: 'p1' }) as never} noToolbar />, { userContext: flagOn() });
    expect(selector()).not.toBeInTheDocument();
    expect(captured.values?.get(SECTOR_ID)).toBe('Finance');
    expect(captured.contentConfig?.relativeDate).toBe('months-1');
  });
});

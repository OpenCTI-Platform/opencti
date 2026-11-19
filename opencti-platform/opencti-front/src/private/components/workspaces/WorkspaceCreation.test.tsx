import React from 'react';
import { screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../utils/tests/test-render';
import WorkspaceCreation from './WorkspaceCreation';
import { WorkspacesLinesPaginationQuery$variables } from './__generated__/WorkspacesLinesPaginationQuery.graphql';

const mocks = vi.hoisted(() => ({
  canImportFromBundle: false,
  handleImport: vi.fn(),
}));

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return { ...actual, graphql: (query: TemplateStringsArray) => query };
});

vi.mock('../../../components/i18n', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../components/i18n')>()),
  useFormatter: () => ({ t_i18n: (value: string) => value }),
}));

vi.mock('../../../utils/hooks/useApiMutation', () => ({
  default: () => [vi.fn()],
}));

vi.mock('../../../utils/markdown/useMarkdownCreationFilesInput', () => ({
  default: () => ({ buildCreationFilesInput: vi.fn(), registerMarkdownImagesController: vi.fn() }),
}));

vi.mock('../../../utils/Security', () => ({
  default: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

// Only the button of the dial is of interest here: the form of the drawer is not rendered
vi.mock('../common/drawer/Drawer', () => ({
  default: ({ controlledDial }: { controlledDial: (props: { onOpen: () => void }) => React.ReactNode }) => <div>{controlledDial({ onOpen: vi.fn() })}</div>,
}));

vi.mock('../../../components/CreateEntityControlledDial', () => ({
  default: () => <button type="button">Create</button>,
}));

// The file import that exists without the dialog: its picker is opened by handleImport
vi.mock('../../../components/dashboard/import-export/useDashboardImport', () => ({
  default: () => ({ handleImport: mocks.handleImport, onChange: vi.fn(), inputRef: { current: null } }),
}));
vi.mock('../../../components/dashboard/import-export/DashboardHiddenImportInput', () => ({
  default: () => <input type="file" aria-label="hidden file input" />,
}));

vi.mock('../settings/config_preset/import/partial/useConfigPresetPartialImportAccess', () => ({
  default: () => mocks.canImportFromBundle,
}));

vi.mock('../settings/config_preset/import/partial/ConfigPresetPartialImportDialog', () => ({
  default: ({ open, type, onChooseFile, onBundleImported }: { open: boolean; type: string; onChooseFile: () => void; onBundleImported: () => void }) => (open
    ? (
        <div role="dialog" aria-label={`import ${type}`}>
          <button type="button" onClick={onChooseFile}>Choose a file</button>
          <button type="button" onClick={onBundleImported}>Bundle imported</button>
        </div>
      )
    : null),
}));

const paginationOptions = {} as WorkspacesLinesPaginationQuery$variables;

describe('WorkspaceCreation, the import of a dashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.canImportFromBundle = false;
  });

  it('opens the file picker at once, as it always did, when the partial import is not available', async () => {
    const { user } = testRender(<WorkspaceCreation paginationOptions={paginationOptions} type="dashboard" />);
    await user.click(screen.getByTestId('ImportDashboard'));
    expect(mocks.handleImport).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('keeps the button, as the e2e tests find it, with or without the dialog', () => {
    [false, true].forEach((canImport) => {
      mocks.canImportFromBundle = canImport;
      const { unmount } = testRender(<WorkspaceCreation paginationOptions={paginationOptions} type="dashboard" />);
      expect(screen.getByTestId('ImportDashboard')).toHaveAccessibleName('Import dashboard');
      unmount();
    });
  });

  it('opens the dialog of the dashboards first when the partial import is available, and no file picker', async () => {
    mocks.canImportFromBundle = true;
    const { user } = testRender(<WorkspaceCreation paginationOptions={paginationOptions} type="dashboard" />);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    await user.click(screen.getByTestId('ImportDashboard'));
    expect(screen.getByRole('dialog', { name: 'import dashboards' })).toBeInTheDocument();
    expect(mocks.handleImport).not.toHaveBeenCalled();
  });

  it('closes the dialog and opens the file picker of the file import when the file is chosen', async () => {
    mocks.canImportFromBundle = true;
    const { user } = testRender(<WorkspaceCreation paginationOptions={paginationOptions} type="dashboard" />);
    await user.click(screen.getByTestId('ImportDashboard'));
    await user.click(screen.getByRole('button', { name: 'Choose a file' }));
    expect(mocks.handleImport).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('tells the list that dashboards were imported from a bundle, and only then', async () => {
    mocks.canImportFromBundle = true;
    const onDashboardsImported = vi.fn();
    const { user } = testRender(<WorkspaceCreation paginationOptions={paginationOptions} type="dashboard" onDashboardsImported={onDashboardsImported} />);
    await user.click(screen.getByTestId('ImportDashboard'));
    await user.click(screen.getByRole('button', { name: 'Choose a file' }));
    expect(onDashboardsImported).not.toHaveBeenCalled();
    await user.click(screen.getByTestId('ImportDashboard'));
    await user.click(screen.getByRole('button', { name: 'Bundle imported' }));
    expect(onDashboardsImported).toHaveBeenCalledTimes(1);
  });

  it('does not fail when nobody listens to the import of a bundle', async () => {
    mocks.canImportFromBundle = true;
    const { user } = testRender(<WorkspaceCreation paginationOptions={paginationOptions} type="dashboard" />);
    await user.click(screen.getByTestId('ImportDashboard'));
    await user.click(screen.getByRole('button', { name: 'Bundle imported' }));
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });
});

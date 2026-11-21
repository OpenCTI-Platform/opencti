import React, { useEffect } from 'react';
import { screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../../utils/tests/test-render';
import CustomViewsSettings from './CustomViewsSettings';

const mocks = vi.hoisted(() => ({
  canImportFromBundle: false,
  handleImport: vi.fn(),
  tableMounts: vi.fn(),
}));

vi.mock('../../../../../components/i18n', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../components/i18n')>()),
  useFormatter: () => ({ t_i18n: (value: string) => value }),
}));

vi.mock('../SubTypeOutletContext', () => ({
  useSubTypeOutletContext: () => ({ subType: { id: 'Report' } }),
}));

vi.mock('../../../../../utils/hooks/useXTMHubResourceLink', () => ({
  useXTMHubResourceLink: () => null,
}));

// The file import that exists without the dialog: its picker is opened by handleImport
vi.mock('./import-export/useCustomViewImport', () => ({
  default: () => ({ handleImport: mocks.handleImport, importing: false, onChange: vi.fn(), inputRef: { current: null } }),
}));
vi.mock('../../../../../components/dashboard/import-export/DashboardHiddenImportInput', () => ({
  default: () => <input type="file" aria-label="hidden file input" />,
}));

// The list is read again when it is mounted again: the mounts are what the screen controls
vi.mock('./CustomViewsSettingsDataTable', () => ({
  default: ({ targetType }: { targetType: string }) => {
    useEffect(() => {
      mocks.tableMounts(targetType);
    }, []);
    return <div data-testid="custom-views-table" />;
  },
}));
vi.mock('./CustomViewFormDrawer', () => ({ default: () => null }));

vi.mock('../../config_preset/import/partial/useConfigPresetPartialImportAccess', () => ({
  default: () => mocks.canImportFromBundle,
}));

vi.mock('../../config_preset/import/partial/ConfigPresetPartialImportDialog', () => ({
  default: ({ open, type, scope, onChooseFile, onBundleImported }: {
    open: boolean;
    type: string;
    scope?: { key: string; value: string };
    onChooseFile: () => void;
    onBundleImported: () => void;
  }) => (open
    ? (
        <div role="dialog" aria-label={`import ${type}`} data-scope={JSON.stringify(scope)}>
          <button type="button" onClick={onChooseFile}>Choose a file</button>
          <button type="button" onClick={onBundleImported}>Bundle imported</button>
        </div>
      )
    : null),
}));

describe('CustomViewsSettings, the import of a custom view', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.canImportFromBundle = false;
  });

  it('opens the file picker at once, as it always did, when the partial import is not available', async () => {
    const { user } = testRender(<CustomViewsSettings />);
    await user.click(screen.getByRole('button', { name: 'Import a custom view' }));
    expect(mocks.handleImport).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('opens the dialog of the custom views first when the partial import is available, scoped to the entity type of the page, and no file picker', async () => {
    mocks.canImportFromBundle = true;
    const { user } = testRender(<CustomViewsSettings />);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Import a custom view' }));
    const dialog = screen.getByRole('dialog', { name: 'import customViews' });
    // Only the views of this entity type are offered: the ones of the other types of the bundle are not
    expect(JSON.parse(dialog.getAttribute('data-scope') as string)).toEqual({ key: 'target_entity_type', value: 'Report' });
    expect(mocks.handleImport).not.toHaveBeenCalled();
  });

  it('closes the dialog and opens the file picker of the file import when the file is chosen, without reading the list again', async () => {
    mocks.canImportFromBundle = true;
    const { user } = testRender(<CustomViewsSettings />);
    await user.click(screen.getByRole('button', { name: 'Import a custom view' }));
    await user.click(screen.getByRole('button', { name: 'Choose a file' }));
    expect(mocks.handleImport).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(mocks.tableMounts).toHaveBeenCalledTimes(1);
  });

  it('reads the list of the views again once views were imported from a bundle, and only then', async () => {
    mocks.canImportFromBundle = true;
    const { user } = testRender(<CustomViewsSettings />);
    expect(mocks.tableMounts).toHaveBeenCalledTimes(1);
    expect(mocks.tableMounts).toHaveBeenCalledWith('Report');
    await user.click(screen.getByRole('button', { name: 'Import a custom view' }));
    await user.click(screen.getByRole('button', { name: 'Bundle imported' }));
    expect(mocks.tableMounts).toHaveBeenCalledTimes(2);
    expect(screen.getByTestId('custom-views-table')).toBeInTheDocument();
  });
});

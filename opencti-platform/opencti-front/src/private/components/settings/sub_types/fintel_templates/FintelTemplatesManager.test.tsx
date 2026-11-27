import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../../utils/tests/test-render';
import FintelTemplatesManager from './FintelTemplatesManager';

const mocks = vi.hoisted(() => ({
  canImportFromBundle: false,
  fetchQuery: vi.fn(),
  // What the read of the page gives back: resolved by default
  refetchResult: () => Promise.resolve() as Promise<unknown>,
  handleError: vi.fn(),
}));

vi.mock('../../../../../components/i18n', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../components/i18n')>()),
  useFormatter: () => ({ t_i18n: (value: string) => value }),
}));

vi.mock('react-relay', async (importOriginal) => ({
  ...(await importOriginal<typeof import('react-relay')>()),
  useFragment: () => ({ id: 'report-entity-setting-id', target_type: 'Report', fintelTemplates: { edges: [] } }),
}));

vi.mock('../SubTypeOutletContext', () => ({
  useSubTypeOutletContext: () => ({ subType: { id: 'Report', settings: {} } }),
}));

// The page of the entity type is read again through its query: the page itself is not rendered here
vi.mock('../SubType', () => ({ subTypeQuery: 'subTypeQuery' }));
vi.mock('../../../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../relay/environment')>()),
  fetchQuery: (...args: unknown[]) => {
    mocks.fetchQuery(...args);
    return { toPromise: () => mocks.refetchResult() };
  },
  handleError: (...args: unknown[]) => mocks.handleError(...args),
}));

vi.mock('../../../../../utils/hooks/useEnterpriseEdition', () => ({ default: () => true }));
vi.mock('./useFintelTemplateImport', () => ({ default: () => [vi.fn(), false] }));
vi.mock('./FintelTemplatesLines', () => ({ default: () => <div data-testid="fintel-templates-lines" /> }));
vi.mock('./FintelTemplateFormDrawer', () => ({ default: () => null }));

vi.mock('../../config_preset/import/partial/useConfigPresetPartialImportAccess', () => ({
  default: () => mocks.canImportFromBundle,
}));

vi.mock('../../config_preset/import/partial/ConfigPresetPartialImportDialog', () => ({
  default: ({ open, type, scope, onChooseFile, onBundleImported }: {
    open: boolean;
    type: string;
    scope?: string;
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

describe('FintelTemplatesManager, the import of a template', () => {
  // The file picker of the file import: a click on the hidden input
  let pickerClicks: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    mocks.canImportFromBundle = false;
    pickerClicks = vi.spyOn(HTMLInputElement.prototype, 'click').mockImplementation(() => undefined);
  });

  afterEach(() => {
    pickerClicks.mockRestore();
  });

  it('opens the file picker at once, as it always did, when the partial import is not available', async () => {
    const { user } = testRender(<FintelTemplatesManager />);
    await user.click(screen.getByRole('button', { name: 'Import a template' }));
    expect(pickerClicks).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('opens the dialog of the fintel templates first when the partial import is available, scoped to the entity type of the page, and no file picker', async () => {
    mocks.canImportFromBundle = true;
    const { user } = testRender(<FintelTemplatesManager />);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Import a template' }));
    const dialog = screen.getByRole('dialog', { name: 'import fintelTemplates' });
    // Only the templates of this entity type are offered: the ones of the other types of the bundle are not
    expect(JSON.parse(dialog.getAttribute('data-scope') as string)).toEqual('Report');
    expect(pickerClicks).not.toHaveBeenCalled();
  });

  it('closes the dialog and opens the file picker of the file import when the file is chosen, without reading the templates again', async () => {
    mocks.canImportFromBundle = true;
    const { user } = testRender(<FintelTemplatesManager />);
    await user.click(screen.getByRole('button', { name: 'Import a template' }));
    await user.click(screen.getByRole('button', { name: 'Choose a file' }));
    expect(pickerClicks).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(mocks.fetchQuery).not.toHaveBeenCalled();
  });

  it('reads the entity type and its templates again from the network once templates were imported from a bundle', async () => {
    mocks.canImportFromBundle = true;
    const { user } = testRender(<FintelTemplatesManager />);
    await user.click(screen.getByRole('button', { name: 'Import a template' }));
    await user.click(screen.getByRole('button', { name: 'Bundle imported' }));
    expect(mocks.fetchQuery).toHaveBeenCalledWith('subTypeQuery', { id: 'Report' }, { fetchPolicy: 'network-only' });
    expect(mocks.handleError).not.toHaveBeenCalled();
  });

  it('says that the templates could not be read again, instead of leaving the failure unhandled', async () => {
    mocks.canImportFromBundle = true;
    const failure = new Error('Network error');
    mocks.refetchResult = () => Promise.reject(failure);
    const { user } = testRender(<FintelTemplatesManager />);
    await user.click(screen.getByRole('button', { name: 'Import a template' }));
    await user.click(screen.getByRole('button', { name: 'Bundle imported' }));
    await waitFor(() => expect(mocks.handleError).toHaveBeenCalledWith(failure));
    mocks.refetchResult = () => Promise.resolve();
  });
});

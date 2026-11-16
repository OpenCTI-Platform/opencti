import React from 'react';
import { beforeEach, describe, expect, it, Mock, vi } from 'vitest';
import { act, screen, waitFor } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender from '../../../../utils/tests/test-render';
import useConfigPresetPartialImportAccess from '../config_preset/import/partial/useConfigPresetPartialImportAccess';
import ThemeImporter from './ThemeImporter';

vi.mock('../config_preset/import/partial/useConfigPresetPartialImportAccess', () => ({ default: vi.fn() }));

type Rendered = ReturnType<typeof testRender>;

const renderImporter = () => testRender(<ThemeImporter handleRefetch={vi.fn()} onThemesImported={vi.fn()} paginationOptions={{ count: 25 }} />);
const operation = ({ relayEnv }: Rendered, name: string) => relayEnv.mock.getAllOperations().find((candidate) => candidate.request.node.operation.name === name)!;
const resolve = async (rendered: Rendered, name: string, resolvers: Record<string, () => unknown>) => {
  await waitFor(() => expect(operation(rendered, name)).toBeDefined());
  await act(async () => {
    rendered.relayEnv.mock.resolve(operation(rendered, name), MockPayloadGenerator.generate(operation(rendered, name), resolvers));
  });
};
const fileCard = () => screen.getByRole('button', { name: /^Import a theme file/ });
const bundleCard = () => screen.getByRole('button', { name: /^Import from bundle platform config/ });
const activeStep = () => document.querySelector('.MuiStepLabel-label.Mui-active')?.textContent;

// Opens the dialog of a BYPASS user with the flag on
const openDialog = async () => {
  (useConfigPresetPartialImportAccess as Mock).mockReturnValue(true);
  const rendered = renderImporter();
  await rendered.user.click(screen.getByTestId('import-theme-btn'));
  return rendered;
};

describe('ThemeImporter', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('keeps the theme file import as it is without the partial import: no dialog', async () => {
    (useConfigPresetPartialImportAccess as Mock).mockReturnValue(false);
    const { user } = renderImporter();
    await user.click(screen.getByTestId('import-theme-btn'));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByTestId('import-theme-btn').querySelector('input[type="file"]')).not.toBeNull();
  });

  it('starts with the two methods only, without a Next nor a Cancel: a click on a card is the choice', async () => {
    const { relayEnv } = await openDialog();
    expect(activeStep()).toEqual('Method');
    expect(fileCard()).toHaveAttribute('aria-pressed', 'false');
    expect(bundleCard()).toHaveAttribute('aria-pressed', 'false');
    expect(screen.queryByRole('button', { name: 'Next' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument();
    expect(screen.queryByTestId('config-preset-partial-import-file')).not.toBeInTheDocument();
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
  });

  it('goes to the file of the bundle at once, and back to the methods with the bundle highlighted', async () => {
    const { user } = await openDialog();
    await user.click(bundleCard());
    expect(activeStep()).toEqual('Select file');
    expect(screen.getByTestId('config-preset-partial-import-file')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Back' }));
    expect(activeStep()).toEqual('Method');
    expect(bundleCard()).toHaveAttribute('aria-pressed', 'true');
  });

  it('opens the file picker of the theme file import at once, as without the dialog, with no step of its own', async () => {
    const { user } = await openDialog();
    const fileInput = screen.getByTestId('import-theme-file') as HTMLInputElement;
    const openPicker = vi.spyOn(fileInput, 'click');
    await user.click(fileCard());
    expect(openPicker).toHaveBeenCalledTimes(1);
    // The dialog waits for a file: no second step, it closes once the file is picked
    expect(activeStep()).toEqual('Method');
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });

  it('imports the theme file picked and closes the dialog, the import telling its outcome as before', async () => {
    const rendered = await openDialog();
    const file = new File(['{}'], 'theme.json', { type: 'application/json' });
    await rendered.user.upload(screen.getByTestId('import-theme-file'), file);
    expect(operation(rendered, 'ThemeImporterImportMutation').request.variables).toEqual({ file });
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('keeps the bundle import mounted while it runs: no dismissal until its result, shown in the last step', async () => {
    const rendered = await openDialog();
    await rendered.user.click(bundleCard());
    await rendered.user.upload(screen.getByTestId('config-preset-partial-import-file'), new File(['zip'], 'bundle.zip', { type: 'application/zip' }));
    await resolve(rendered, 'ConfigPresetPartialImportPreviewMutation', {
      ConfigPresetPartialImportPreview: () => ({
        bundle_name: null,
        default_mode: 'COPY',
        type: { key: 'branding', label: 'Branding', description: '', lockedByEnterpriseEdition: false, modes: ['OVERWRITE', 'COPY'], items: [{ key: 'theme--a', label: 'Night', translatable: false, exists: false, conflict: false }] },
      }),
    });
    await rendered.user.click(screen.getByTestId('config-preset-partial-import-submit'));

    // The import runs on the server
    expect(screen.getByRole('button', { name: 'Back' })).toBeDisabled();
    expect(screen.queryByRole('button', { name: 'close' })).not.toBeInTheDocument();
    await rendered.user.keyboard('{Escape}');
    expect(screen.getByRole('dialog')).toBeInTheDocument();

    await resolve(rendered, 'ConfigPresetPartialImportMutation', {
      ConfigPresetPartialImportOutput: () => ({
        results: [{ type: 'branding', key: 'theme--a', status: 'CREATED', reason: null, label: 'Night', translatable: false }],
        counts: { created: 1, overwritten: 0, skipped: 0, failed: 0 },
      }),
    });
    expect(activeStep()).toEqual('Done');
    expect(screen.getByTestId('config-preset-partial-import-result')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'close' })).toBeInTheDocument();
  });
});

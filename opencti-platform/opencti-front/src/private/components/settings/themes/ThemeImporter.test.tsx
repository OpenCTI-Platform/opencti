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
const next = () => screen.getByTestId('config-preset-partial-import-next');
const activeStep = () => document.querySelector('.MuiStepLabel-label.Mui-active')?.textContent;

// Opens the dialog and goes to the second step of the chosen method
const openOnMethod = async (method: 'file' | 'bundle') => {
  (useConfigPresetPartialImportAccess as Mock).mockReturnValue(true);
  const rendered = renderImporter();
  await rendered.user.click(screen.getByTestId('import-theme-btn'));
  await rendered.user.click(method === 'file' ? fileCard() : bundleCard());
  await rendered.user.click(next());
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

  it('starts with the two methods only, and goes on once one is chosen', async () => {
    (useConfigPresetPartialImportAccess as Mock).mockReturnValue(true);
    const { user, relayEnv } = renderImporter();
    await user.click(screen.getByTestId('import-theme-btn'));
    expect(activeStep()).toEqual('Method');
    expect(fileCard()).toHaveAttribute('aria-pressed', 'false');
    expect(bundleCard()).toHaveAttribute('aria-pressed', 'false');
    expect(screen.queryByTestId('import-theme-file')).not.toBeInTheDocument();
    expect(screen.queryByTestId('config-preset-partial-import-file')).not.toBeInTheDocument();
    expect(next()).toBeDisabled();

    await user.click(bundleCard());
    expect(bundleCard()).toHaveAttribute('aria-pressed', 'true');
    await user.click(next());
    expect(activeStep()).toEqual('Select file');
    expect(screen.getByTestId('config-preset-partial-import-file')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Back' }));
    expect(activeStep()).toEqual('Method');
    expect(bundleCard()).toHaveAttribute('aria-pressed', 'true');
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
  });

  it('imports the theme file picked in the second step, then shows it in the last one', async () => {
    const rendered = await openOnMethod('file');
    expect(activeStep()).toEqual('Select file');
    expect(screen.getByTestId('import-theme-submit')).toBeDisabled();
    const file = new File(['{}'], 'theme.json', { type: 'application/json' });
    await rendered.user.upload(screen.getByTestId('import-theme-file'), file);
    await rendered.user.click(screen.getByTestId('import-theme-submit'));
    expect(operation(rendered, 'ThemeImporterImportMutation').request.variables).toEqual({ file });
    await resolve(rendered, 'ThemeImporterImportMutation', { Theme: () => ({ id: 'theme-id', name: 'Imported theme' }) });
    expect(activeStep()).toEqual('Done');
    expect(screen.getByTestId('config-preset-partial-import-file-result')).toHaveTextContent('Imported theme');
  });

  it('keeps the bundle import mounted while it runs: no dismissal until its result, shown in the last step', async () => {
    const rendered = await openOnMethod('bundle');
    await rendered.user.upload(screen.getByTestId('config-preset-partial-import-file'), new File(['zip'], 'bundle.zip', { type: 'application/zip' }));
    await resolve(rendered, 'ConfigPresetPartialImportPreviewMutation', {
      ConfigPresetPartialImportPreview: () => ({
        bundle_name: null,
        default_mode: 'COPY',
        type: { key: 'branding', modes: ['OVERWRITE', 'COPY'], items: [{ key: 'theme--a', label: 'Night', translatable: false, exists: false, conflict: false }] },
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

import React from 'react';
import { beforeEach, describe, expect, it, Mock, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import useConfigPresetPartialImportAccess from '../config_preset/import/partial/useConfigPresetPartialImportAccess';
import ThemeImporter from './ThemeImporter';

vi.mock('../config_preset/import/partial/useConfigPresetPartialImportAccess', () => ({ default: vi.fn() }));

const renderImporter = () => testRender(<ThemeImporter handleRefetch={vi.fn()} onThemesImported={vi.fn()} paginationOptions={{ count: 25 }} />);

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

  it('offers the theme file or the configuration bundle to a BYPASS user with the flag on', async () => {
    (useConfigPresetPartialImportAccess as Mock).mockReturnValue(true);
    const { user, relayEnv } = renderImporter();
    await user.click(screen.getByTestId('import-theme-btn'));
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Import a theme file/ })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByRole('button', { name: /^Import from bundle platform config/ })).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByTestId('import-theme-file')).toBeInTheDocument();
    expect(screen.getByTestId('import-theme-submit')).toBeDisabled();

    await user.click(screen.getByRole('button', { name: /^Import from bundle platform config/ }));
    expect(screen.getByRole('button', { name: /^Import from bundle platform config/ })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByTestId('config-preset-partial-import-file')).toBeInTheDocument();
    expect(screen.queryByTestId('import-theme-file')).not.toBeInTheDocument();
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
  });

  it('imports the theme file picked in the dialog', async () => {
    (useConfigPresetPartialImportAccess as Mock).mockReturnValue(true);
    const { user, relayEnv } = renderImporter();
    await user.click(screen.getByTestId('import-theme-btn'));
    const file = new File(['{}'], 'theme.json', { type: 'application/json' });
    await user.upload(screen.getByTestId('import-theme-file'), file);
    await user.click(screen.getByTestId('import-theme-submit'));
    const [importOperation] = relayEnv.mock.getAllOperations();
    expect(importOperation.request.node.operation.name).toEqual('ThemeImporterImportMutation');
    expect(importOperation.request.variables).toEqual({ file });
  });
});

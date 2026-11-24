import React from 'react';
import { beforeEach, describe, expect, it, Mock, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import useConfigPresetPartialImportAccess from '../../settings/config_preset/import/partial/useConfigPresetPartialImportAccess';
import FormImport from './FormImport';

vi.mock('../../settings/config_preset/import/partial/useConfigPresetPartialImportAccess', () => ({ default: vi.fn() }));

type Rendered = ReturnType<typeof testRender>;

const operation = ({ relayEnv }: Rendered, name: string) => relayEnv.mock.getAllOperations().find((candidate) => candidate.request.node.operation.name === name);
const trigger = () => screen.getByTitle('Import form intake');
const fileInput = () => screen.getByTestId('import-form-intake-file') as HTMLInputElement;
const fileCard = () => screen.getByRole('button', { name: /^Import a form intake file/ });
const bundleCard = () => screen.getByRole('button', { name: /^Import from bundle platform config/ });
const activeStep = () => document.querySelector('.MuiStepLabel-label.Mui-active')?.textContent;

describe('FormImport', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('opens the file picker at once without the partial import (not a BYPASS user, or the flag off): no dialog', async () => {
    (useConfigPresetPartialImportAccess as Mock).mockReturnValue(false);
    const { user } = testRender(<FormImport />);
    const openPicker = vi.spyOn(fileInput(), 'click');
    await user.click(trigger());
    expect(openPicker).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('offers the form intake file and the configuration bundle to a BYPASS user, without opening the file picker', async () => {
    (useConfigPresetPartialImportAccess as Mock).mockReturnValue(true);
    const { user } = testRender(<FormImport />);
    const openPicker = vi.spyOn(fileInput(), 'click');
    await user.click(trigger());
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(activeStep()).toEqual('Method');
    expect(fileCard()).toHaveAttribute('aria-pressed', 'false');
    expect(bundleCard()).toHaveAttribute('aria-pressed', 'false');
    expect(openPicker).not.toHaveBeenCalled();
  });

  it('opens the file picker of the form intake file import from its card, and keeps waiting for a file', async () => {
    (useConfigPresetPartialImportAccess as Mock).mockReturnValue(true);
    const { user } = testRender(<FormImport />);
    await user.click(trigger());
    const openPicker = vi.spyOn(fileInput(), 'click');
    await user.click(fileCard());
    expect(openPicker).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(activeStep()).toEqual('Method');
  });

  it('imports the form intake file picked and closes the dialog, as the import did before', async () => {
    (useConfigPresetPartialImportAccess as Mock).mockReturnValue(true);
    const rendered = testRender(<FormImport />);
    await rendered.user.click(trigger());
    const file = new File(['{}'], 'form.json', { type: 'application/json' });
    await rendered.user.upload(fileInput(), file);
    expect(operation(rendered, 'FormImportMutation')?.request.variables).toEqual({ file });
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('reads the bundle for the form intakes type, and never runs the form intake file import for it', async () => {
    (useConfigPresetPartialImportAccess as Mock).mockReturnValue(true);
    const rendered = testRender(<FormImport />);
    await rendered.user.click(trigger());
    await rendered.user.click(bundleCard());
    expect(activeStep()).toEqual('Select file');
    await rendered.user.upload(screen.getByTestId('config-preset-partial-import-file'), new File(['zip'], 'bundle.zip', { type: 'application/zip' }));
    await waitFor(() => expect(operation(rendered, 'ConfigPresetPartialImportPreviewMutation')).toBeDefined());
    expect(operation(rendered, 'ConfigPresetPartialImportPreviewMutation')?.request.variables).toMatchObject({ type: 'formIntakes' });
    expect(operation(rendered, 'FormImportMutation')).toBeUndefined();
  });

  it('goes back from the file of the bundle to the methods, the bundle highlighted', async () => {
    (useConfigPresetPartialImportAccess as Mock).mockReturnValue(true);
    const { user } = testRender(<FormImport />);
    await user.click(trigger());
    await user.click(bundleCard());
    expect(activeStep()).toEqual('Select file');
    await user.click(screen.getByRole('button', { name: 'Back' }));
    expect(activeStep()).toEqual('Method');
    expect(bundleCard()).toHaveAttribute('aria-pressed', 'true');
  });

  it('shows no trigger and no dialog when the import is driven externally', () => {
    (useConfigPresetPartialImportAccess as Mock).mockReturnValue(true);
    testRender(<FormImport hideTrigger />);
    expect(screen.queryByTitle('Import form intake')).not.toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
});

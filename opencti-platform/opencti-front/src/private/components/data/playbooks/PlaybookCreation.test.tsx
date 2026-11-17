import React from 'react';
import { beforeEach, describe, expect, it, Mock, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import useConfigPresetPartialImportAccess from '../../settings/config_preset/import/partial/useConfigPresetPartialImportAccess';
import PlaybookCreation from './PlaybookCreation';

vi.mock('../../settings/config_preset/import/partial/useConfigPresetPartialImportAccess', () => ({ default: vi.fn() }));

const fileInput = () => document.querySelector('input[type="file"]') as HTMLInputElement;

describe('PlaybookCreation import', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('opens the file picker at once without the partial import: no dialog', async () => {
    (useConfigPresetPartialImportAccess as Mock).mockReturnValue(false);
    const { user } = testRender(<PlaybookCreation />);
    const openPicker = vi.spyOn(fileInput(), 'click');
    await user.click(screen.getByTestId('ImporPlaybook'));
    expect(openPicker).toHaveBeenCalled();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('offers the playbook file and the configuration bundle, the file card opening the picker of the playbook file import', async () => {
    (useConfigPresetPartialImportAccess as Mock).mockReturnValue(true);
    const { user } = testRender(<PlaybookCreation />);
    const openPicker = vi.spyOn(fileInput(), 'click');
    await user.click(screen.getByTestId('ImporPlaybook'));
    expect(openPicker).not.toHaveBeenCalled();
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Import from bundle platform config/ })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /^Import a playbook file/ }));
    expect(openPicker).toHaveBeenCalled();
  });
});

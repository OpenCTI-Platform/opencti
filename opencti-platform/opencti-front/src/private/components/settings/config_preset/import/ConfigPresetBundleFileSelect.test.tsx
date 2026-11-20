import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import testRender from '../../../../../utils/tests/test-render';
import ConfigPresetBundleFileSelect, { CONFIG_PRESET_MAX_ZIP_SIZE } from './ConfigPresetBundleFileSelect';

const renderField = () => {
  const onFileChange = vi.fn();
  const rendered = testRender(<ConfigPresetBundleFileSelect value={null} onFileChange={onFileChange} data-testid="bundle-file" />);
  return { ...rendered, onFileChange };
};
// A file of the given size, without allocating it
const fileOfSize = (name: string, type: string, size: number) => {
  const file = new File(['zip'], name, { type });
  Object.defineProperty(file, 'size', { value: size });
  return file;
};

describe('ConfigPresetBundleFileSelect', () => {
  it('hands a zip over', async () => {
    const { user, onFileChange } = renderField();
    const file = new File(['zip'], 'bundle.zip', { type: 'application/zip' });
    await user.upload(screen.getByTestId('bundle-file'), file);
    expect(onFileChange).toHaveBeenCalledWith(file);
  });

  it('refuses a file that is not a zip, with the reason', async () => {
    const { onFileChange } = renderField();
    fireEvent.change(screen.getByTestId('bundle-file'), { target: { files: [new File(['text'], 'notes.txt', { type: 'text/plain' })] } });
    expect(await screen.findByText('This file is not in the specified format')).toBeInTheDocument();
    expect(onFileChange).not.toHaveBeenCalled();
  });

  it('refuses a zip above the limit of the backend, with the reason', async () => {
    const { onFileChange } = renderField();
    fireEvent.change(screen.getByTestId('bundle-file'), { target: { files: [fileOfSize('big.zip', 'application/zip', CONFIG_PRESET_MAX_ZIP_SIZE + 1)] } });
    expect(await screen.findByText('This file is too large')).toBeInTheDocument();
    expect(onFileChange).not.toHaveBeenCalled();
    expect(CONFIG_PRESET_MAX_ZIP_SIZE).toBe(50 * 1024 * 1024);
  });
});

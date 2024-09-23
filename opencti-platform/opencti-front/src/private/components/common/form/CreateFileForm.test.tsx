import { describe, it, expect, vi } from 'vitest';
import React from 'react';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import CreateFileForm from './CreateFileForm';

describe('Component: CreateFileForm', () => {
  it('should not be displayed if not opened', () => {
    testRender(
      <CreateFileForm
        isOpen={false}
        onClose={() => {}}
        onReset={() => {}}
        onSubmit={() => {}}
      />,
    );

    const child = screen.queryByText('Create a file');
    expect(child).not.toBeInTheDocument();
  });

  it('should be displayed if opened', () => {
    testRender(
      <CreateFileForm
        isOpen={true}
        onClose={() => {}}
        onReset={() => {}}
        onSubmit={() => {}}
      />,
    );

    const child = screen.queryByText('Create a file');
    expect(child).toBeInTheDocument();
  });

  it('should not submit if form is not valid', async () => {
    const onSubmit = vi.fn();

    const { user } = testRender(
      <CreateFileForm
        isOpen={true}
        onClose={() => {}}
        onReset={() => {}}
        onSubmit={onSubmit}
      />,
    );

    await user.click(screen.getByRole('button', { name: 'Create' }));
    expect(onSubmit).toHaveBeenCalledTimes(0);
  });

  it('should submit the values filled in the form', async () => {
    const onSubmit = vi.fn();

    const { user } = testRender(
      <CreateFileForm
        isOpen={true}
        onClose={() => {}}
        onReset={() => {}}
        onSubmit={onSubmit}
      />,
    );

    await user.type(screen.getByLabelText('Name'), 'Super file');
    await user.click(screen.getByRole('button', { name: 'Create' }));
    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect(onSubmit).toHaveBeenCalledWith(
      {
        name: 'Super file',
        type: 'text/html',
        fileMarkings: [],
      },
      expect.anything(),
    );
  });
});

import { describe, expect, it, vi } from 'vitest';
import React from 'react';
import { screen } from '@testing-library/react';
import testRender from '../../../../../utils/tests/test-render';
import FintelTemplateForm from './FintelTemplateForm';

describe('Component: FintelTemplateForm', () => {
  it('should not submit if form is not valid', async () => {
    const onSubmit = vi.fn();
    const onSubmitField = vi.fn();

    const { user } = testRender(
      <FintelTemplateForm
        onClose={() => {}}
        onSubmit={onSubmit}
        onSubmitField={onSubmitField}
      />,
    );

    await user.click(screen.getByRole('button', { name: 'Create' }));
    expect(onSubmit).toHaveBeenCalledTimes(0);
  });

  it('should submit the values filled in the form', async () => {
    const onSubmit = vi.fn();
    const onSubmitField = vi.fn();

    const { user } = testRender(
      <FintelTemplateForm
        onClose={() => {}}
        onSubmit={onSubmit}
        onSubmitField={onSubmitField}
      />,
    );

    await user.type(screen.getByLabelText('Name *'), 'MyFintelTemplate');
    await user.click(screen.getByRole('button', { name: 'Create' }));
    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect(onSubmit).toHaveBeenCalledWith(
      {
        name: 'MyFintelTemplate',
        description: null,
        published: false,
      },
      expect.anything(),
    );
  });
});

import { describe, it, expect, vi } from 'vitest';
import React from 'react';
import { screen } from '@testing-library/react';
import ContentTemplateForm from './ContentTemplateForm';
import testRender from '../../../../utils/tests/test-render';
import type { Template } from '../../../../utils/outcome_template/template';

describe('Component: ContentTemplateForm', () => {
  const templates = [
    { id: 'template 1', name: 'template 1' },
    { id: 'template 2', name: 'template 2' },
    { id: 'template 3', name: 'template 3' },
  ] as Template[];

  it('should not be displayed if not opened', () => {
    testRender(
      <ContentTemplateForm
        isOpen={false}
        onClose={() => {}}
        onReset={() => {}}
        onSubmit={() => {}}
        templates={templates}
      />,
    );

    const child = screen.queryByText('Create a content from a template');
    expect(child).not.toBeInTheDocument();
  });

  it('should be displayed if opened', () => {
    testRender(
      <ContentTemplateForm
        isOpen={true}
        onClose={() => {}}
        onReset={() => {}}
        onSubmit={() => {}}
        templates={templates}
      />,
    );

    const child = screen.queryByText('Create a content from a template');
    expect(child).toBeInTheDocument();
  });

  it('should not submit if form is not valid', async () => {
    const onSubmit = vi.fn();

    const { user } = testRender(
      <ContentTemplateForm
        isOpen={true}
        onClose={() => {}}
        onReset={() => {}}
        onSubmit={onSubmit}
        templates={templates}
      />,
    );

    const createButton = screen.getByRole('button', { name: 'Create' });
    await user.click(createButton);
    expect(onSubmit).toHaveBeenCalledTimes(0);

    await user.type(screen.getByLabelText('Name'), 'Super template');
    await user.click(createButton);
    expect(onSubmit).toHaveBeenCalledTimes(0);
  });

  it('should submit the values filled in the form', async () => {
    const onSubmit = vi.fn();

    const { user } = testRender(
      <ContentTemplateForm
        isOpen={true}
        onClose={() => {}}
        onReset={() => {}}
        onSubmit={onSubmit}
        templates={templates}
      />,
    );

    await user.type(screen.getByLabelText('Name'), 'Super template');
    await user.click(screen.getByLabelText('Template'));
    await user.click(screen.getByText('template 2'));
    await user.click(screen.getByRole('button', { name: 'Create' }));
    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect(onSubmit).toHaveBeenCalledWith(
      {
        name: 'Super template',
        template: 'template 2',
        type: 'text/html',
        fileMarkings: [],
        maxMarkings: [],
      },
      expect.anything(),
    );
  });
});

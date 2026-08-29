import { describe, expect, it, vi } from 'vitest';
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

    // 'Name', not 'Name *': the library Input puts the required marker in its
    // own `aria-hidden` span, so the asterisk is deliberately outside the
    // accessible name. MUI concatenated it. `required` is still announced —
    // through `aria-required` on the input.
    await user.type(screen.getByLabelText('Name'), 'MyFintelTemplate');
    await user.click(screen.getByRole('button', { name: 'Create' }));
    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect(onSubmit).toHaveBeenCalledWith(
      {
        name: 'MyFintelTemplate',
        description: null,
        published: false,
        default: false,
        include_cover_page_by_default: true,
        include_back_page_by_default: true,
      },
      expect.anything(),
    );
  });

  it('should submit export default toggle changes in edit mode', async () => {
    const onSubmit = vi.fn();
    const onSubmitField = vi.fn();

    const { user } = testRender(
      <FintelTemplateForm
        onClose={() => {}}
        onSubmit={onSubmit}
        onSubmitField={onSubmitField}
        defaultValues={{
          name: 'MyFintelTemplate',
          description: null,
          published: true,
          default: false,
          include_cover_page_by_default: true,
          include_back_page_by_default: true,
        }}
        editingProps={{ onDefaultToggle: vi.fn() }}
      />,
    );

    await user.click(screen.getByLabelText('Include cover page by default'));

    expect(onSubmitField).toHaveBeenCalledWith('include_cover_page_by_default', false);
  });
});

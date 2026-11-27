import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { Field, Form, Formik } from 'formik';
import * as React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import RichTextField from './RichTextField';
import testRender from '../../utils/tests/test-render';

const ai = vi.hoisted(() => ({ enabled: false, configured: false }));
vi.mock('../../utils/hooks/useAI', () => ({ default: () => ai }));

// Ask AI runs Relay mutations; this stands in for it and returns a fixed answer.
vi.mock('@components/common/form/TextFieldAskAI', () => ({
  default: ({ setFieldValue }: { setFieldValue: (value: string) => void }) => (
    <button type="button" onClick={() => setFieldValue('<p>From AI</p>')}>Ask AI</button>
  ),
}));

const renderField = (props: Record<string, unknown> = {}, content = '<p>Hello</p>') => testRender(
  <Formik initialValues={{ content }} onSubmit={() => {}}>
    <Form>
      <Field component={RichTextField} name="content" label="Content" {...props} />
    </Form>
  </Formik>,
);

const editingArea = () => screen.findByRole('textbox', { name: 'Content' });

describe('RichTextField', () => {
  it('renders the Formik value in an editing area named by the label', async () => {
    renderField();
    expect(await editingArea()).toHaveTextContent('Hello');
  });

  // #19919: @filigran/rich-text-editor rendered a MenuItem outside a menu list
  // in its colour popovers, which MUI 9.5 refuses (MenuListContext is missing).
  it.each(['Text color', 'Background color'])('opens the %s panel', async (tool) => {
    const { user } = renderField();
    await editingArea();
    await user.click(screen.getByRole('button', { name: tool }));
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
  });

  it('reports every edit to Formik and to onChange', async () => {
    const onChange = vi.fn();
    const { user } = renderField({ onChange });
    await editingArea();
    await user.click(screen.getByRole('button', { name: 'Source HTML' }));
    const source = screen.getByRole('textbox', { name: /Content/ });
    await user.clear(source);
    await user.type(source, '<p>Bye</p>');
    await waitFor(() => expect(onChange).toHaveBeenLastCalledWith('content', '<p>Bye</p>'));
  });

  it('keeps a disabled field selectable when it reports selections (mapping)', async () => {
    renderField({ disabled: true, onTextSelection: vi.fn() });
    const area = await editingArea();
    expect(area).toHaveAttribute('aria-readonly', 'true');
    expect(area).not.toHaveAttribute('aria-disabled');
  });

  // Selects the first word of the editing area as a mouse would, then releases.
  const selectFirstWord = (area: HTMLElement) => {
    const text = area.querySelector('p')!.firstChild!;
    const range = document.createRange();
    range.setStart(text, 0);
    range.setEnd(text, 5);
    window.getSelection()!.removeAllRanges();
    window.getSelection()!.addRange(range);
    fireEvent.mouseUp(area);
  };

  it('reports a selection made in the field (mapping)', async () => {
    const onTextSelection = vi.fn();
    renderField({ disabled: true, onTextSelection });
    selectFirstWord(await editingArea());
    expect(onTextSelection).toHaveBeenCalledWith('Hello');
  });

  it('ignores a selection made in fullscreen, whose dialog would hide the mapping drawer', async () => {
    const onTextSelection = vi.fn();
    const { user } = renderField({ disabled: true, onTextSelection });
    await editingArea();
    await user.click(screen.getByRole('button', { name: 'Fullscreen' }));
    const dialog = await screen.findByRole('dialog');
    selectFirstWord(within(dialog).getByRole('textbox', { name: 'Content' }));
    expect(onTextSelection).not.toHaveBeenCalled();
  });

  it('disables the field otherwise', async () => {
    renderField({ disabled: true });
    expect(await editingArea()).toHaveAttribute('aria-disabled', 'true');
  });

  it('reports focus, and submits the value on blur (edit forms save on blur)', async () => {
    const onFocus = vi.fn();
    const onSubmit = vi.fn();
    renderField({ onFocus, onSubmit });
    const area = await editingArea();
    // Events rather than area.focus(): a real focus makes ProseMirror scroll to
    // the selection, which jsdom cannot measure (no Range.getClientRects).
    fireEvent.focus(area);
    fireEvent.focusIn(area);
    await waitFor(() => expect(onFocus).toHaveBeenCalledWith('content'));
    fireEvent.blur(area);
    fireEvent.focusOut(area);
    await waitFor(() => expect(onSubmit).toHaveBeenCalledWith('content', '<p>Hello</p>'));
  });

  describe('Ask AI', () => {
    afterEach(() => {
      ai.enabled = false;
      ai.configured = false;
    });

    it('is hidden while AI is not configured', async () => {
      ai.enabled = true;
      renderField({ askAi: true });
      await editingArea();
      expect(screen.queryByRole('button', { name: 'Ask AI' })).not.toBeInTheDocument();
    });

    it('writes the answer to the field and submits it', async () => {
      ai.enabled = true;
      ai.configured = true;
      const onSubmit = vi.fn();
      const { user } = renderField({ askAi: true, onSubmit });
      await editingArea();
      await user.click(screen.getByRole('button', { name: 'Ask AI' }));
      expect(onSubmit).toHaveBeenCalledWith('content', '<p>From AI</p>');
      await waitFor(async () => expect(await editingArea()).toHaveTextContent('From AI'));
    });
  });
});

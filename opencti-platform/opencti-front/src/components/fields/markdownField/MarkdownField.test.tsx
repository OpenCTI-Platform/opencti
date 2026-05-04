import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { Field, Formik } from 'formik';
import testRender from '../../../utils/tests/test-render';
import MarkdownField from './MarkdownField';

const commitMutationMock = vi.fn();

vi.mock('../../../relay/environment', async () => {
  const actual = await vi.importActual('../../../relay/environment');
  return {
    ...actual,
    commitMutation: (config: {
      onCompleted?: (response: {
        stixCoreObjectEdit?: {
          importPush?: { id?: string; name?: string } | null;
        } | null;
      }) => void;
      onError?: (error: Error) => void;
    }) => commitMutationMock(config),
  };
});

const renderMarkdownField = (
  initialValue = '',
  props: Record<string, unknown> = {},
) => {
  return testRender(
    <Formik
      initialValues={{ description: initialValue }}
      onSubmit={() => {}}
    >
      <Field
        name="description"
        component={MarkdownField}
        label="Description"
        {...props}
      />
    </Formik>,
  );
};

describe('Component: MarkdownField', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    commitMutationMock.mockReset();
    commitMutationMock.mockImplementation(({ onCompleted }) => {
      onCompleted?.({
        stixCoreObjectEdit: {
          importPush: { id: 'import/global/default-uploaded-file', name: 'default-uploaded-file.png' },
        },
      });
    });
  });

  it('inserts image markdown at current cursor position from file picker', async () => {
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:picker');
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    vi.spyOn(globalThis.crypto, 'randomUUID').mockReturnValue('00000000-0000-0000-0000-000000000001');

    const { container } = renderMarkdownField('Hello world');

    const textArea = await screen.findByRole('textbox') as HTMLTextAreaElement;
    textArea.focus();
    textArea.setSelectionRange(5, 5);

    const fileInput = container.querySelector('input[type="file"]') as HTMLInputElement;
    expect(fileInput).toBeInTheDocument();

    fireEvent.change(fileInput, {
      target: {
        files: [new File(['file-content'], 'cat.png', { type: 'image/png' })],
      },
    });

    await waitFor(() => {
      expect(textArea.value).toBe('Hello![cat.png](opencti-image://temp/00000000-0000-0000-0000-000000000001) world');
    });
  });

  it('inserts dropped image files and ignores non-image files', async () => {
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:drop');
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    vi.spyOn(globalThis.crypto, 'randomUUID').mockReturnValue('00000000-0000-0000-0000-000000000002');

    renderMarkdownField('');

    const textArea = await screen.findByRole('textbox') as HTMLTextAreaElement;

    fireEvent.drop(textArea, {
      dataTransfer: {
        files: [
          new File(['file-content'], 'image.png', { type: 'image/png' }),
          new File(['not-image'], 'notes.txt', { type: 'text/plain' }),
        ],
        types: ['Files'],
      },
    });

    await waitFor(() => {
      expect(textArea.value).toContain('![image.png](opencti-image://temp/00000000-0000-0000-0000-000000000002)');
      expect(textArea.value).not.toContain('notes.txt');
    });
  });

  it('preserves typed text when dropping an image before deferred formik sync', async () => {
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:drop-typed');
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    vi.spyOn(globalThis.crypto, 'randomUUID').mockReturnValue('00000000-0000-0000-0000-000000000009');

    renderMarkdownField('');

    const textArea = await screen.findByRole('textbox') as HTMLTextAreaElement;
    fireEvent.input(textArea, { target: { value: 'typed before drop' } });

    fireEvent.drop(textArea, {
      dataTransfer: {
        files: [new File(['file-content'], 'dropped.png', { type: 'image/png' })],
        types: ['Files'],
      },
    });

    await waitFor(() => {
      expect(textArea.value).toContain('typed before drop');
      expect(textArea.value).toContain('![dropped.png](opencti-image://temp/00000000-0000-0000-0000-000000000009)');
      expect(textArea.value).not.toBe('![dropped.png](opencti-image://temp/00000000-0000-0000-0000-000000000009)');
    });
  });

  it('shows and clears dashed outline indicator while dragging files over write textarea', async () => {
    renderMarkdownField('');

    const textArea = await screen.findByRole('textbox') as HTMLTextAreaElement;

    fireEvent.dragEnter(textArea, {
      dataTransfer: {
        types: ['Files'],
      },
    });

    expect(textArea.style.outline).toContain('dashed');

    fireEvent.dragLeave(textArea, {
      dataTransfer: {
        types: ['Files'],
      },
    });

    expect(textArea.style.outline).toBe('');
  });

  it('inserts pasted clipboard image as temp markdown image link', async () => {
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:paste');
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    vi.spyOn(globalThis.crypto, 'randomUUID').mockReturnValue('00000000-0000-0000-0000-000000000008');

    renderMarkdownField('prefix ');

    const textArea = await screen.findByRole('textbox') as HTMLTextAreaElement;
    textArea.focus();
    textArea.setSelectionRange(7, 7);

    const screenshot = new File(['clipboard-image'], 'screenshot.png', { type: 'image/png' });
    fireEvent.paste(textArea, {
      clipboardData: {
        items: [
          {
            kind: 'file',
            type: 'image/png',
            getAsFile: () => screenshot,
          },
        ],
      },
    });

    await waitFor(() => {
      expect(textArea.value).toBe('prefix ![screenshot.png](opencti-image://temp/00000000-0000-0000-0000-000000000008)');
    });
  });

  it('preserves typed text when pasting an image before deferred formik sync', async () => {
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:paste-typed');
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    vi.spyOn(globalThis.crypto, 'randomUUID').mockReturnValue('00000000-0000-0000-0000-000000000010');

    renderMarkdownField('');

    const textArea = await screen.findByRole('textbox') as HTMLTextAreaElement;
    fireEvent.input(textArea, { target: { value: 'typed before paste' } });

    const pastedFile = new File(['clipboard-image'], 'pasted.png', { type: 'image/png' });
    fireEvent.paste(textArea, {
      clipboardData: {
        items: [
          {
            kind: 'file',
            type: 'image/png',
            getAsFile: () => pastedFile,
          },
        ],
      },
    });

    await waitFor(() => {
      expect(textArea.value).toContain('typed before paste');
      expect(textArea.value).toContain('![pasted.png](opencti-image://temp/00000000-0000-0000-0000-000000000010)');
      expect(textArea.value).not.toBe('![pasted.png](opencti-image://temp/00000000-0000-0000-0000-000000000010)');
    });
  });

  it('revokes object URL when temp image markdown is removed', async () => {
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:remove');
    const revokeObjectURL = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    vi.spyOn(globalThis.crypto, 'randomUUID').mockReturnValue('00000000-0000-0000-0000-000000000003');

    const { container } = renderMarkdownField('');

    const textArea = await screen.findByRole('textbox') as HTMLTextAreaElement;
    const fileInput = container.querySelector('input[type="file"]') as HTMLInputElement;

    fireEvent.change(fileInput, {
      target: {
        files: [new File(['file-content'], 'to-remove.png', { type: 'image/png' })],
      },
    });

    await waitFor(() => {
      expect(textArea.value).toContain('opencti-image://temp/00000000-0000-0000-0000-000000000003');
    });

    fireEvent.change(textArea, { target: { value: '' } });
    fireEvent.blur(textArea, { relatedTarget: document.body });

    await waitFor(() => {
      expect(revokeObjectURL).toHaveBeenCalledWith('blob:remove');
    });
  });

  it('does not revoke object URL when temp image markdown is moved by cut and paste', async () => {
    vi.useFakeTimers();
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:move');
    const revokeObjectURL = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    vi.spyOn(globalThis.crypto, 'randomUUID').mockReturnValue('00000000-0000-0000-0000-000000000005');

    try {
      const { container } = renderMarkdownField('prefix ');
      const textArea = await screen.findByRole('textbox') as HTMLTextAreaElement;
      const fileInput = container.querySelector('input[type="file"]') as HTMLInputElement;

      fireEvent.change(fileInput, {
        target: {
          files: [new File(['file-content'], 'move-me.png', { type: 'image/png' })],
        },
      });

      const tokenUrl = 'opencti-image://temp/00000000-0000-0000-0000-000000000005';

      await waitFor(() => {
        expect(textArea.value).toContain(tokenUrl);
      });

      fireEvent.change(textArea, { target: { value: 'prefix ' } });
      fireEvent.change(textArea, { target: { value: `prefix ![move-me.png](${tokenUrl})` } });

      act(() => {
        vi.advanceTimersByTime(350);
      });

      expect(revokeObjectURL).not.toHaveBeenCalledWith('blob:move');
    } finally {
      vi.useRealTimers();
    }
  });

  it('keeps temp image mapping when moving the same link after preview to write switch', async () => {
    vi.useFakeTimers();
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:preview-write-move');
    const revokeObjectURL = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    vi.spyOn(globalThis.crypto, 'randomUUID').mockReturnValue('00000000-0000-0000-0000-000000000006');

    try {
      const { container } = renderMarkdownField('prefix ');
      const textArea = await screen.findByRole('textbox') as HTMLTextAreaElement;
      const fileInput = container.querySelector('input[type="file"]') as HTMLInputElement;

      fireEvent.change(fileInput, {
        target: {
          files: [new File(['file-content'], 'dashboard1 (2).png', { type: 'image/png' })],
        },
      });

      const imageMarkdown = '![dashboard1 (2).png](opencti-image://temp/00000000-0000-0000-0000-000000000006)';

      await waitFor(() => {
        expect(textArea.value).toContain(imageMarkdown);
      });

      fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
      fireEvent.click(screen.getByRole('button', { name: 'Write' }));

      fireEvent.change(textArea, { target: { value: 'prefix ' } });
      act(() => {
        vi.advanceTimersByTime(350);
      });
      fireEvent.change(textArea, { target: { value: `prefix ${imageMarkdown}` } });

      act(() => {
        vi.advanceTimersByTime(350);
      });

      expect(revokeObjectURL).not.toHaveBeenCalledWith('blob:preview-write-move');
      fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
      await waitFor(() => {
        expect(screen.getByRole('img', { name: 'dashboard1 (2).png' })).toBeInTheDocument();
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it('keeps cursor position after deferred sync while editing in the middle of text', async () => {
    vi.useFakeTimers();

    try {
      renderMarkdownField('Hello world');

      const textArea = await screen.findByRole('textbox') as HTMLTextAreaElement;
      textArea.focus();
      textArea.setSelectionRange(5, 5);

      fireEvent.input(textArea, {
        target: {
          value: 'HelloX world',
          selectionStart: 6,
          selectionEnd: 6,
        },
      });

      // Simulate browser cursor state right after typing.
      textArea.setSelectionRange(6, 6);

      act(() => {
        vi.advanceTimersByTime(200);
      });

      expect(textArea.value).toBe('HelloX world');
      expect(textArea.selectionStart).toBe(6);
      expect(textArea.selectionEnd).toBe(6);
    } finally {
      vi.useRealTimers();
    }
  });

  it('revokes all temp object URLs on unmount', async () => {
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:unmount');
    const revokeObjectURL = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    vi.spyOn(globalThis.crypto, 'randomUUID').mockReturnValue('00000000-0000-0000-0000-000000000004');

    const { container, unmount } = renderMarkdownField('');

    const fileInput = container.querySelector('input[type="file"]') as HTMLInputElement;

    fireEvent.change(fileInput, {
      target: {
        files: [new File(['file-content'], 'to-cleanup.png', { type: 'image/png' })],
      },
    });

    await waitFor(() => {
      expect(screen.getByRole('textbox')).toHaveValue('![to-cleanup.png](opencti-image://temp/00000000-0000-0000-0000-000000000004)');
    });

    unmount();

    expect(revokeObjectURL).toHaveBeenCalledWith('blob:unmount');
  });

  it('finalizes temp image links to embedded URL on blur submit', async () => {
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:finalize');
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    vi.spyOn(globalThis.crypto, 'randomUUID').mockReturnValue('00000000-0000-0000-0000-000000000007');
    commitMutationMock.mockImplementationOnce(({ onCompleted }) => {
      onCompleted?.({
        stixCoreObjectEdit: {
          importPush: { id: 'import/global/uploaded-1', name: 'to-finalize-00000000.png' },
        },
      });
    });

    const onSubmit = vi.fn();
    const { container } = renderMarkdownField('', {
      onSubmit,
      uploadEntityId: 'entity--test',
    });

    const textArea = await screen.findByRole('textbox') as HTMLTextAreaElement;
    const fileInput = container.querySelector('input[type="file"]') as HTMLInputElement;

    fireEvent.change(fileInput, {
      target: {
        files: [new File(['file-content'], 'to-finalize.png', { type: 'image/png' })],
      },
    });

    await waitFor(() => {
      expect(textArea.value).toContain('opencti-image://temp/00000000-0000-0000-0000-000000000007');
    });

    fireEvent.blur(textArea, { relatedTarget: document.body });

    await waitFor(() => {
      expect(textArea.value).toContain('embedded/to-finalize-00000000.png');
    });
    expect(onSubmit).toHaveBeenCalledWith(
      'description',
      '![to-finalize.png](embedded/to-finalize-00000000.png)',
    );
  });

  it('shows validation after tabbing from textarea to internal upload button', async () => {
    testRender(
      <Formik
        initialValues={{ description: '' }}
        validate={(values) => {
          if (!values.description?.trim()) {
            return { description: 'Description is required' };
          }
          return {};
        }}
        onSubmit={() => {}}
      >
        <Field
          name="description"
          component={MarkdownField}
          label="Description"
        />
      </Formik>,
    );

    const textArea = await screen.findByRole('textbox');
    const uploadButton = screen.getByRole('button', { name: 'Paste, drop, or click to add images' });

    fireEvent.focus(textArea);
    fireEvent.blur(textArea, { relatedTarget: uploadButton });
    fireEvent.focus(uploadButton);

    await waitFor(() => {
      expect(screen.getByText('Description is required')).toBeInTheDocument();
    });
  });
});

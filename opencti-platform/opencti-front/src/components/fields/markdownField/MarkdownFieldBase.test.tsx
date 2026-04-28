import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import MarkdownFieldBase from './MarkdownFieldBase';

const useMarkdownImagesMock = vi.fn();

vi.mock('./hooks/useMarkdownImages', () => ({
  default: (args: unknown) => useMarkdownImagesMock(args),
}));

const buildHookReturn = (overrides: Record<string, unknown> = {}) => {
  const latestMarkdownRef = { current: '' };
  return {
    fileInputRef: { current: null },
    dragFeedback: 'none',
    isDragInvalid: false,
    isDragOverWrite: false,
    handleDragEnter: vi.fn(),
    handleDragLeave: vi.fn(),
    handleDragOver: vi.fn(),
    handleDrop: vi.fn(),
    handleFilePickerChange: vi.fn(),
    handlePaste: vi.fn(),
    handleUploadButtonClick: vi.fn(),
    toolbarCommands: undefined,
    cleanupRemovedAttachments: vi.fn(),
    finalizeMarkdown: vi.fn(async (markdown: string) => markdown),
    syncLatestMarkdown: vi.fn((nextValue: string) => {
      latestMarkdownRef.current = nextValue;
    }),
    latestMarkdownRef,
    pendingCleanupTimeoutRef: { current: new Map() },
    registryRef: { current: { resolvePreviewImageUrl: (url: string) => url, size: 0 } },
    ...overrides,
  };
};

const renderBase = (props: Record<string, unknown> = {}) => {
  return testRender(
    <MarkdownFieldBase
      name="description"
      value=""
      onValueChange={vi.fn()}
      onFlushValue={vi.fn()}
      onMarkTouched={vi.fn()}
      onSubmit={vi.fn()}
      label="Description"
      {...props}
    />,
  );
};

describe('Component: MarkdownFieldBase', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useMarkdownImagesMock.mockReset();
  });

  it('submits latest typed value on blur when autoPersistOnBlur is false', async () => {
    const onSubmit = vi.fn();
    const hookState = buildHookReturn();

    useMarkdownImagesMock.mockReturnValue(hookState);

    renderBase({
      autoPersistOnBlur: false,
      onSubmit,
      onValueChange: vi.fn((nextValue: string) => {
        hookState.latestMarkdownRef.current = nextValue;
      }),
    });

    const textArea = await screen.findByRole('textbox') as HTMLTextAreaElement;

    fireEvent.change(textArea, { target: { value: 'typed latest value' } });
    fireEvent.blur(textArea, { relatedTarget: document.body });

    expect(hookState.finalizeMarkdown).not.toHaveBeenCalled();
    expect(onSubmit).toHaveBeenCalledWith('description', 'typed latest value');
  });

  it('calls finalizeMarkdown on blur only when autoPersistOnBlur is true', async () => {
    const trueState = buildHookReturn({
      latestMarkdownRef: { current: 'draft before finalize' },
      finalizeMarkdown: vi.fn(async () => 'finalized markdown'),
    });
    useMarkdownImagesMock.mockReturnValue(trueState);

    const onSubmitTrue = vi.fn();
    const { unmount } = renderBase({
      autoPersistOnBlur: true,
      onSubmit: onSubmitTrue,
    });

    const trueTextArea = await screen.findByRole('textbox') as HTMLTextAreaElement;
    fireEvent.blur(trueTextArea, { relatedTarget: document.body });

    await waitFor(() => {
      expect(trueState.finalizeMarkdown).toHaveBeenCalledWith('draft before finalize');
      expect(onSubmitTrue).toHaveBeenCalledWith('description', 'finalized markdown');
    });

    unmount();

    const falseState = buildHookReturn({
      latestMarkdownRef: { current: 'draft without finalize' },
      finalizeMarkdown: vi.fn(async () => 'should-not-be-used'),
    });
    useMarkdownImagesMock.mockReturnValue(falseState);

    const onSubmitFalse = vi.fn();
    renderBase({
      autoPersistOnBlur: false,
      onSubmit: onSubmitFalse,
    });

    const falseTextArea = await screen.findByRole('textbox') as HTMLTextAreaElement;
    fireEvent.blur(falseTextArea, { relatedTarget: document.body });

    expect(falseState.finalizeMarkdown).not.toHaveBeenCalled();
    await waitFor(() => {
      expect(onSubmitFalse).toHaveBeenCalledWith('description', 'draft without finalize');
    });
  });
});

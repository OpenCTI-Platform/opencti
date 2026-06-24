import { RefObject, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { MESSAGING$ } from '../../../../relay/environment';
import { getImageFiles, getImageFilesFromClipboardData, getMarkdownImageDragFeedback, isSvgImageFile } from '../core/markdownImageFieldHelpers';
import { insertImageAtCursor, MarkdownTempAttachmentRegistry } from '../core/markdownImagePreviewUtils';
import type { MarkdownImagesTab } from '../core/markdownImagesController';

type UseMarkdownImageInteractionsArgs = {
  activeTab: MarkdownImagesTab;
  disabled?: boolean;
  t_i18n: (value: string) => string;
  containerRef: RefObject<HTMLDivElement | null>;
  latestMarkdownRef: RefObject<string>;
  registryRef: RefObject<MarkdownTempAttachmentRegistry>;
  pushDraftAndSyncLatest: (nextValue: string, shouldValidate?: boolean) => void;
  maxImageSizeBytes: number;
};

const useMarkdownImageInteractions = ({
  activeTab,
  disabled,
  t_i18n,
  containerRef,
  latestMarkdownRef,
  registryRef,
  pushDraftAndSyncLatest,
  maxImageSizeBytes,
}: UseMarkdownImageInteractionsArgs) => {
  const [dragFeedback, setDragFeedback] = useState<'none' | 'valid' | 'invalid'>('none');

  const textAreaRef = useRef<HTMLTextAreaElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const dragDepthRef = useRef(0);

  const hasFilePayload = (dataTransfer?: DataTransfer | null): boolean => {
    if (!dataTransfer) {
      return false;
    }
    return Array.from(dataTransfer.types ?? []).includes('Files');
  };

  const resetDragFeedback = useCallback(() => {
    dragDepthRef.current = 0;
    setDragFeedback('none');
  }, []);

  const isDragOverWrite = activeTab === 'write' && dragFeedback !== 'none';
  const isDragInvalid = dragFeedback === 'invalid';

  const resolveTextArea = useCallback((): HTMLTextAreaElement | null => {
    if (textAreaRef.current) {
      return textAreaRef.current;
    }

    const textArea = containerRef.current?.querySelector('textarea') ?? null;
    if (textArea) {
      textAreaRef.current = textArea;
    }
    return textArea;
  }, [containerRef]);

  const insertImages = useCallback((files: File[]) => {
    const containsSvg = files.some((file) => isSvgImageFile(file));
    if (containsSvg) {
      MESSAGING$.notifyError(t_i18n('SVG images are not supported'));
    }

    const imageFiles = getImageFiles(files);
    if (imageFiles.length === 0 || disabled) {
      return;
    }

    const oversized = imageFiles.filter((f) => f.size > maxImageSizeBytes);
    if (oversized.length > 0) {
      MESSAGING$.notifyError(t_i18n('Image files must not exceed 5 MB'));
    }

    const validFiles = imageFiles.filter((f) => f.size <= maxImageSizeBytes);
    if (validFiles.length === 0) {
      return;
    }

    const textArea = resolveTextArea();
    const cursor = textArea?.selectionStart ?? latestMarkdownRef.current.length;

    let nextCursor = cursor;
    let nextMarkdown = latestMarkdownRef.current;
    for (let i = 0; i < validFiles.length; i += 1) {
      const file = validFiles[i];
      const attachment = registryRef.current.createTempAttachment(file);
      const result = insertImageAtCursor(nextMarkdown, nextCursor, attachment.token, file.name || 'image');
      nextMarkdown = result.markdown;
      nextCursor = result.nextCursor;
    }

    pushDraftAndSyncLatest(nextMarkdown);

    requestAnimationFrame(() => {
      const activeTextArea = resolveTextArea();
      if (activeTextArea) {
        activeTextArea.focus();
        activeTextArea.setSelectionRange(nextCursor, nextCursor);
      }
    });
  }, [disabled, latestMarkdownRef, maxImageSizeBytes, pushDraftAndSyncLatest, registryRef, resolveTextArea, t_i18n]);

  const handleFilePickerChange = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files ? Array.from(event.target.files) : [];
    insertImages(files);
    event.target.value = '';
  }, [insertImages]);

  const handleUploadButtonClick = useCallback(() => {
    if (disabled || activeTab !== 'write') {
      return;
    }
    fileInputRef.current?.click();
  }, [activeTab, disabled]);

  const handleDrop = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    resetDragFeedback();
    if (disabled || activeTab !== 'write') {
      return;
    }
    const files = event.dataTransfer.files ? Array.from(event.dataTransfer.files) : [];
    insertImages(files);
  }, [activeTab, disabled, insertImages, resetDragFeedback]);

  const handleDragEnter = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    if (disabled || activeTab !== 'write' || !hasFilePayload(event.dataTransfer)) {
      return;
    }
    event.preventDefault();
    dragDepthRef.current += 1;
    setDragFeedback(getMarkdownImageDragFeedback(event.dataTransfer));
  }, [activeTab, disabled]);

  const handleDragLeave = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    if (disabled || activeTab !== 'write' || !hasFilePayload(event.dataTransfer)) {
      return;
    }
    event.preventDefault();
    dragDepthRef.current = Math.max(0, dragDepthRef.current - 1);
    if (dragDepthRef.current === 0) {
      setDragFeedback('none');
    }
  }, [activeTab, disabled]);

  const handleDragOver = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    if (!disabled && activeTab === 'write' && hasFilePayload(event.dataTransfer)) {
      setDragFeedback(getMarkdownImageDragFeedback(event.dataTransfer));
    }
  }, [activeTab, disabled]);

  const handlePaste = useCallback((event: React.ClipboardEvent<HTMLDivElement>) => {
    if (disabled || activeTab !== 'write') {
      return;
    }

    const files = getImageFilesFromClipboardData(event.clipboardData);
    if (files.length === 0) {
      return;
    }

    event.preventDefault();
    insertImages(files);
  }, [activeTab, disabled, insertImages]);

  useEffect(() => {
    if (activeTab !== 'write' && dragFeedback !== 'none') {
      resetDragFeedback();
    }
  }, [activeTab, dragFeedback, resetDragFeedback]);

  const toolbarCommands = useMemo(() => (disabled ? [] : undefined), [disabled]);

  return {
    fileInputRef,
    dragFeedback,
    isDragInvalid,
    isDragOverWrite,
    handleDragEnter,
    handleDragLeave,
    handleDragOver,
    handleDrop,
    handleFilePickerChange,
    handlePaste,
    handleUploadButtonClick,
    toolbarCommands,
  };
};

export default useMarkdownImageInteractions;

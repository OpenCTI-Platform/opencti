import React, { CSSProperties, FocusEvent, ReactElement, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import ReactMde from 'react-mde';
import InputLabel from '@mui/material/InputLabel';
import FormHelperText from '@mui/material/FormHelperText';
import { AddPhotoAlternateOutlined } from '@mui/icons-material';
import { isNil } from 'ramda';
import Button from '../../common/button/Button';
import { MESSAGING$ } from '../../../relay/environment';
import useAI from '../../../utils/hooks/useAI';
import TextFieldAskAI from '../../../private/components/common/form/TextFieldAskAI';
import { useFormatter } from '../../i18n';
import MarkdownDisplay from '../../markdownDisplay/MarkdownDisplay';
import {
  cleanupRemovedTempAttachments,
  extractEmbeddedStoragePathsFromMarkdown,
  getMarkdownImageDragFeedback,
  getImageFiles,
  getImageFilesFromClipboardData,
  isSvgImageFile,
} from './markdownImageFieldHelpers';
import { insertImageAtCursor, MarkdownTempAttachmentRegistry } from './markdownImageTempUtils';
import useMarkdownImageUpload from './useMarkdownImageUpload';

export type MarkdownTab = 'write' | 'preview';

type MarkdownFieldBaseProps = {
  name: string;
  value: string;
  onValueChange: (nextValue: string, shouldValidate?: boolean) => void;
  onFlushValue?: (shouldValidate?: boolean) => void;
  onMarkTouched?: (nextTouched: boolean) => void;
  errorMessage?: string;
  showValidationError?: boolean;
  required?: boolean;
  onFocus?: (name: string) => void;
  onSubmit?: (name: string, value: string) => void;
  onSelect?: (value: string) => void;
  label?: React.ReactNode;
  style?: CSSProperties;
  disabled?: boolean;
  controlledSelectedTab?: MarkdownTab;
  controlledSetSelectTab?: (tab: MarkdownTab) => void;
  height?: number;
  askAi?: boolean;
  uploadEntityId?: string;
  uploadFileMarkings?: string[];
  finalizeOnBlur?: boolean;
  registerFinalize?: (finalize: (uploadEntityIdOverride?: string) => Promise<string>) => void;
};

const TEMP_CLEANUP_DELAY_MS = 300;
const MAX_IMAGE_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB

const MarkdownFieldBase = ({
  name,
  value,
  onValueChange,
  onFlushValue,
  onMarkTouched,
  errorMessage,
  showValidationError = false,
  required = false,
  onFocus,
  onSubmit,
  onSelect,
  label,
  style,
  disabled,
  controlledSelectedTab,
  controlledSetSelectTab,
  height,
  askAi,
  uploadEntityId,
  uploadFileMarkings,
  finalizeOnBlur = true,
  registerFinalize,
}: MarkdownFieldBaseProps): ReactElement => {
  const { t_i18n } = useFormatter();
  const { fullyActive } = useAI();
  const [selectedTab, setSelectedTab] = useState<MarkdownTab>('write');
  const [draftValue, setDraftValue] = useState(value ?? '');
  const [dragFeedback, setDragFeedback] = useState<'none' | 'valid' | 'invalid'>('none');

  const containerRef = useRef<HTMLDivElement | null>(null);
  const textAreaRef = useRef<HTMLTextAreaElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const pendingCleanupTimeoutRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
  const latestMarkdownRef = useRef(draftValue);
  const submittedEmbeddedPathsRef = useRef(new Set(extractEmbeddedStoragePathsFromMarkdown(value ?? '')));
  const isFieldFocusedRef = useRef(false);
  // Tracks how many nested dragEnter events are unmatched by dragLeave events.
  // The browser fires dragLeave+dragEnter when the cursor moves between child elements,
  // so a simple boolean would flicker. The indicator only clears when this counter reaches 0,
  // meaning the drag has left the entire component.
  const dragDepthRef = useRef(0);
  const registryRef = useRef(new MarkdownTempAttachmentRegistry());

  const { finalizeTempImageUrls } = useMarkdownImageUpload({
    uploadEntityId,
    uploadFileMarkings,
  });

  const showError = !isNil(errorMessage) && showValidationError;
  const activeTab = controlledSelectedTab ?? selectedTab;

  const hasFilePayload = (dataTransfer?: DataTransfer | null): boolean => {
    if (!dataTransfer) {
      return false;
    }
    return Array.from(dataTransfer.types ?? []).includes('Files');
  };

  const isDragOverWrite = activeTab === 'write' && dragFeedback !== 'none';
  const isDragInvalid = dragFeedback === 'invalid';

  useEffect(() => {
    const next = value ?? '';
    if (next === latestMarkdownRef.current) {
      return;
    }

    // Keep local typing state authoritative while focused to avoid
    // cursor jumps when the Formik wrapper syncs value asynchronously.
    if (isFieldFocusedRef.current) {
      return;
    }

    latestMarkdownRef.current = next;
    setDraftValue(next);
    submittedEmbeddedPathsRef.current = new Set(extractEmbeddedStoragePathsFromMarkdown(next));
  }, [value]);

  const pushDraftValue = useCallback((nextValue: string, shouldValidate = false) => {
    latestMarkdownRef.current = nextValue;
    setDraftValue(nextValue);
    onValueChange(nextValue, shouldValidate);
  }, [onValueChange]);

  const finalizeMarkdown = useCallback(async (
    markdown = latestMarkdownRef.current,
    uploadEntityIdOverride?: string,
  ): Promise<string> => {
    const finalized = await finalizeTempImageUrls(markdown, registryRef.current, (token) => {
      pendingCleanupTimeoutRef.current.delete(token);
      registryRef.current.removeTempAttachment(token);
    }, {
      uploadEntityIdOverride,
    });

    if (finalized !== markdown) {
      latestMarkdownRef.current = finalized;
      setDraftValue(finalized);
      onValueChange(finalized, false);
    }

    return finalized;
  }, [finalizeTempImageUrls, onValueChange]);

  useEffect(() => {
    if (!registerFinalize) {
      return undefined;
    }

    registerFinalize((uploadEntityIdOverride?: string) => finalizeMarkdown(undefined, uploadEntityIdOverride));
    return () => registerFinalize(() => Promise.resolve(latestMarkdownRef.current));
  }, [finalizeMarkdown, registerFinalize]);

  const resolveTextArea = useCallback((): HTMLTextAreaElement | null => {
    if (textAreaRef.current) {
      return textAreaRef.current;
    }

    const textArea = containerRef.current?.querySelector('textarea') ?? null;
    if (textArea) {
      textAreaRef.current = textArea;
    }
    return textArea;
  }, []);

  const insertImagesAtCursor = useCallback((files: File[]) => {
    const containsSvg = files.some((file) => isSvgImageFile(file));
    if (containsSvg) {
      MESSAGING$.notifyError(t_i18n('SVG images are not supported'));
    }

    const imageFiles = getImageFiles(files);
    if (imageFiles.length === 0 || disabled) {
      return;
    }

    const oversized = imageFiles.filter((f) => f.size > MAX_IMAGE_SIZE_BYTES);
    if (oversized.length > 0) {
      MESSAGING$.notifyError(t_i18n('Image files must not exceed 5 MB'));
    }
    const validFiles = imageFiles.filter((f) => f.size <= MAX_IMAGE_SIZE_BYTES);
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

    pushDraftValue(nextMarkdown);

    requestAnimationFrame(() => {
      const activeTextArea = resolveTextArea();
      if (activeTextArea) {
        activeTextArea.focus();
        activeTextArea.setSelectionRange(nextCursor, nextCursor);
      }
    });
  }, [disabled, pushDraftValue, resolveTextArea]);

  const handleFilePickerChange = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files ? Array.from(event.target.files) : [];
    insertImagesAtCursor(files);
    event.target.value = '';
  }, [insertImagesAtCursor]);

  const handleUploadButtonClick = useCallback(() => {
    if (disabled || activeTab !== 'write') {
      return;
    }
    fileInputRef.current?.click();
  }, [activeTab, disabled]);

  const handleDrop = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    dragDepthRef.current = 0;
    setDragFeedback('none');
    if (disabled || activeTab !== 'write') {
      return;
    }
    const files = event.dataTransfer.files ? Array.from(event.dataTransfer.files) : [];
    insertImagesAtCursor(files);
  }, [activeTab, disabled, insertImagesAtCursor]);

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
    insertImagesAtCursor(files);
  }, [activeTab, disabled, insertImagesAtCursor]);

  const internalOnFocus = (event: FocusEvent<HTMLDivElement>) => {
    isFieldFocusedRef.current = true;

    const { nodeName } = (event.relatedTarget as HTMLElement) || {};
    if ((nodeName === 'INPUT' || nodeName === undefined) && typeof onFocus === 'function') {
      onFocus(name);
    }
  };

  const internalOnBlur = async (event: FocusEvent<HTMLDivElement>) => {
    if (event.currentTarget.contains(event.relatedTarget)) {
      const blurTarget = event.target as HTMLElement | null;
      const nextTarget = event.relatedTarget as HTMLElement | null;
      const movedFromTextareaToButton = blurTarget?.tagName === 'TEXTAREA' && nextTarget?.tagName === 'BUTTON';

      // Tabbing from editor textarea to internal action buttons should still mark the field
      // as touched so validation feedback appears immediately.
      if (movedFromTextareaToButton) {
        onFlushValue?.(false);
        onMarkTouched?.(true);
      }
      return;
    }

    isFieldFocusedRef.current = false;
    onFlushValue?.(false);
    onMarkTouched?.(true);

    let submitValue = latestMarkdownRef.current;
    if (finalizeOnBlur) {
      submitValue = await finalizeMarkdown(submitValue);
    }

    const nextEmbeddedPaths = new Set(extractEmbeddedStoragePathsFromMarkdown(submitValue));
    submittedEmbeddedPathsRef.current = nextEmbeddedPaths;

    cleanupRemovedTempAttachments({
      pendingCleanupTimeoutRef,
      latestMarkdownRef,
      isFieldFocusedRef,
      registry: registryRef.current,
      delayMs: TEMP_CLEANUP_DELAY_MS,
    }, submitValue, true);

    if (typeof onSubmit === 'function') {
      onSubmit(name, submitValue);
    }
  };

  const internalOnSelect = () => {
    const selection = window.getSelection()?.toString() ?? '';
    if (typeof onSelect === 'function' && selection.length > 2 && disabled) {
      onSelect(selection.trim());
    }
  };

  useEffect(() => {
    return () => {
      const pendingTimeouts = Array.from(pendingCleanupTimeoutRef.current.values());
      for (let i = 0; i < pendingTimeouts.length; i += 1) {
        clearTimeout(pendingTimeouts[i]);
      }
      pendingCleanupTimeoutRef.current.clear();
      registryRef.current.cleanupAllTempAttachments();
    };
  }, []);

  useEffect(() => {
    if (activeTab !== 'write' && dragFeedback !== 'none') {
      dragDepthRef.current = 0;
      setDragFeedback('none');
    }
  }, [activeTab, dragFeedback]);

  const markdownPreviewResolver = useCallback((url: string) => {
    return registryRef.current.resolvePreviewImageUrl(url);
  }, []);

  const toolbarCommands = useMemo(() => (disabled ? [] : undefined), [disabled]);

  return (
    <div
      ref={containerRef}
      style={{ ...style, position: 'relative' }}
      className={showError ? 'error' : 'main'}
      onBlur={internalOnBlur}
      onFocus={internalOnFocus}
      onDrop={handleDrop}
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDragOver={handleDragOver}
      onPaste={handlePaste}
    >
      <InputLabel shrink={true} required={required} error={showError}>
        {label}
      </InputLabel>

      <input
        ref={fileInputRef}
        type="file"
        accept="image/png,image/jpeg,image/gif,image/webp"
        multiple
        style={{ display: 'none' }}
        onChange={handleFilePickerChange}
      />

      <ReactMde
        value={draftValue}
        readOnly={disabled}
        onChange={(nextValue) => {
          pushDraftValue(nextValue);

          if (registryRef.current.size > 0 || pendingCleanupTimeoutRef.current.size > 0) {
            cleanupRemovedTempAttachments({
              pendingCleanupTimeoutRef,
              latestMarkdownRef,
              isFieldFocusedRef,
              registry: registryRef.current,
              delayMs: TEMP_CLEANUP_DELAY_MS,
            }, nextValue);
          }
        }}
        selectedTab={controlledSelectedTab ?? selectedTab}
        onTabChange={(tab) => {
          if (controlledSetSelectTab) {
            controlledSetSelectTab(tab);
          } else {
            setSelectedTab(tab);
          }
        }}
        generateMarkdownPreview={(markdown) => Promise.resolve(
          <div onMouseUp={() => internalOnSelect()}>
            <MarkdownDisplay
              content={markdown}
              remarkGfmPlugin={true}
              commonmark={true}
              resolveImageUrl={markdownPreviewResolver}
              enableImagePreviewModal={true}
            />
          </div>,
        )}
        toolbarCommands={toolbarCommands}
        l18n={{
          write: t_i18n('Write'),
          preview: t_i18n('Preview'),
          uploadingImage: t_i18n('Uploading image'),
          pasteDropSelect: t_i18n('Paste'),
        }}
        childProps={{
          textArea: {
            onSelect: internalOnSelect,
            style: {
              height: height ?? 100,
              ...(isDragOverWrite && {
                outline: isDragInvalid
                  ? '2px dashed rgba(211, 47, 47, 0.95)'
                  : '2px dashed rgba(46, 125, 50, 0.95)',
                outlineOffset: '-2px',
                cursor: isDragInvalid ? 'not-allowed' : 'copy',
              }),
            },
          },
        }}
        minEditorHeight={height ?? 100}
        maxEditorHeight={height ?? 100}
        minPreviewHeight={140}
      />

      {activeTab === 'write' && (
        <Button
          variant="tertiary"
          size="small"
          type="button"
          onClick={handleUploadButtonClick}
          disabled={disabled}
          startIcon={<AddPhotoAlternateOutlined fontSize="small" />}
          sx={{ marginTop: '4px' }}
        >
          {t_i18n('Paste, drop, or click to add images')}
        </Button>
      )}

      {activeTab === 'write' && dragFeedback === 'valid' && (
        <FormHelperText sx={{ marginTop: '2px', color: 'success.main' }}>
          {t_i18n('Release to upload images')}
        </FormHelperText>
      )}

      {activeTab === 'write' && dragFeedback === 'invalid' && (
        <FormHelperText error={true} sx={{ marginTop: '2px' }}>
          {t_i18n('SVG files are not supported. Use PNG, JPG, GIF, or WEBP.')}
        </FormHelperText>
      )}

      {showError && <FormHelperText error={true}>{errorMessage}</FormHelperText>}

      {askAi && fullyActive && (
        <TextFieldAskAI
          currentValue={draftValue}
          setFieldValue={(nextValue: string) => {
            pushDraftValue(nextValue, false);
            onFlushValue?.(false);
            if (typeof onSubmit === 'function') {
              onSubmit(name, nextValue);
            }
          }}
          format="markdown"
          variant="markdown"
          disabled={disabled}
        />
      )}
    </div>
  );
};

export default MarkdownFieldBase;

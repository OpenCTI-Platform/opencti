import React, { CSSProperties, FocusEvent, MouseEvent, ReactElement, useCallback, useRef, useState } from 'react';
import ReactMde from 'react-mde';
import InputLabel from '@mui/material/InputLabel';
import FormHelperText from '@mui/material/FormHelperText';
import { AddPhotoAlternateOutlined } from '@mui/icons-material';
import { isNil } from 'ramda';
import Button from '../../common/button/Button';
import useAI from '../../../utils/hooks/useAI';
import useHelper from '../../../utils/hooks/useHelper';
import TextFieldAskAI from '../../../private/components/common/form/TextFieldAskAI';
import { useFormatter } from '../../i18n';
import MarkdownDisplay from '../../markdownDisplay/MarkdownDisplay';
import type { MarkdownImagesController } from './core/markdownImagesController';
import useMarkdownImages from './hooks/useMarkdownImages';
import { MARKDOWN_IMAGE_UPLOAD } from '../../../utils/platformModulesHelper';

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
  autoPersistOnBlur?: boolean;
  registerMarkdownImagesController?: (controller: MarkdownImagesController) => void;
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
  autoPersistOnBlur,
  registerMarkdownImagesController,
}: MarkdownFieldBaseProps): ReactElement => {
  const { t_i18n } = useFormatter();
  const { enabled, configured } = useAI();
  const { isFeatureEnable } = useHelper();
  const isImageUploadEnabled = isFeatureEnable(MARKDOWN_IMAGE_UPLOAD);
  const [selectedTab, setSelectedTab] = useState<MarkdownTab>('write');
  const [draftValue, setDraftValue] = useState(value ?? '');

  const containerRef = useRef<HTMLDivElement | null>(null);
  const isFieldFocusedRef = useRef(false);
  const initialValueOnFocus = useRef<string | null>(null);
  const suppressInternalButtonBlurValidationRef = useRef(false);

  const showError = !isNil(errorMessage) && showValidationError;
  const activeTab = controlledSelectedTab ?? selectedTab;

  const pushDraftValue = useCallback((nextValue: string, shouldValidate = false) => {
    setDraftValue(nextValue);
    onValueChange(nextValue, shouldValidate);
  }, [onValueChange]);

  const {
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
    cleanupRemovedAttachments,
    finalizeMarkdown,
    syncLatestMarkdown,
    latestMarkdownRef,
    pendingCleanupTimeoutRef,
    registryRef,
  } = useMarkdownImages({
    activeTab,
    disabled,
    t_i18n,
    containerRef,
    value,
    onValueChange,
    setDraftValue,
    pushDraftValue,
    isFieldFocusedRef,
    registerMarkdownImagesController,
    uploadEntityId,
    uploadFileMarkings,
    tempCleanupDelayMs: TEMP_CLEANUP_DELAY_MS,
    maxImageSizeBytes: MAX_IMAGE_SIZE_BYTES,
    isImageUploadEnabled,
  });

  const internalOnFocus = (event: FocusEvent<HTMLDivElement>) => {
    if (!event.currentTarget.contains(event.relatedTarget)) {
      initialValueOnFocus.current = latestMarkdownRef.current;
    }
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

      if (movedFromTextareaToButton && suppressInternalButtonBlurValidationRef.current) {
        suppressInternalButtonBlurValidationRef.current = false;
        return;
      }

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
    const shouldPersistOnBlur = autoPersistOnBlur ?? true;
    if (shouldPersistOnBlur) {
      submitValue = await finalizeMarkdown(submitValue);
    }

    cleanupRemovedAttachments(submitValue, true);

    const hasChangedSinceFocus = submitValue !== initialValueOnFocus.current;
    if (typeof onSubmit === 'function' && hasChangedSinceFocus) {
      onSubmit(name, submitValue);
    }
  };

  const internalOnSelect = () => {
    const selection = window.getSelection()?.toString() ?? '';
    if (typeof onSelect === 'function' && selection.length > 2 && disabled) {
      onSelect(selection.trim());
    }
  };

  const markdownPreviewResolver = useCallback((url: string) => {
    return registryRef.current.resolvePreviewImageUrl(url);
  }, []);

  const handleUploadButtonMouseDown = (event: MouseEvent<HTMLButtonElement>) => {
    suppressInternalButtonBlurValidationRef.current = true;
    // Prevent the textarea from blurring on mouse click so Formik doesn't mark
    // the field as touched before the user actually leaves the markdown field.
    event.preventDefault();
  };

  const handleUploadButtonMouseLeave = () => {
    suppressInternalButtonBlurValidationRef.current = false;
  };

  const handleUploadButtonClickInternal = () => {
    suppressInternalButtonBlurValidationRef.current = false;
    handleUploadButtonClick();
  };

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
          syncLatestMarkdown(nextValue);
          pushDraftValue(nextValue);

          if (registryRef.current.size > 0 || pendingCleanupTimeoutRef.current.size > 0) {
            cleanupRemovedAttachments(nextValue);
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

      {activeTab === 'write' && isImageUploadEnabled && (
        <Button
          variant="tertiary"
          size="small"
          type="button"
          onMouseDown={handleUploadButtonMouseDown}
          onMouseLeave={handleUploadButtonMouseLeave}
          onClick={handleUploadButtonClickInternal}
          disabled={disabled}
          startIcon={<AddPhotoAlternateOutlined fontSize="small" />}
          sx={{ marginTop: '4px' }}
        >
          {t_i18n('Paste, drop, or click to add images')}
        </Button>
      )}

      {activeTab === 'write' && isImageUploadEnabled && dragFeedback === 'valid' && (
        <FormHelperText sx={{ marginTop: '2px', color: 'success.main' }}>
          {t_i18n('Release to upload images')}
        </FormHelperText>
      )}

      {activeTab === 'write' && isImageUploadEnabled && dragFeedback === 'invalid' && (
        <FormHelperText error={true} sx={{ marginTop: '2px' }}>
          {t_i18n('SVG files are not supported. Use PNG, JPG, GIF, or WEBP.')}
        </FormHelperText>
      )}

      {showError && <FormHelperText error={true}>{errorMessage}</FormHelperText>}

      {askAi && (enabled && configured) && (
        <TextFieldAskAI
          currentValue={draftValue}
          setFieldValue={(nextValue: string) => {
            syncLatestMarkdown(nextValue);
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

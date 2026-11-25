import TextFieldAskAI from '@components/common/form/TextFieldAskAI';
import { RichTextField } from '@filigran/design-system/rich-text-field';
import Box from '@mui/material/Box';
import { FieldProps, useField } from 'formik';
import { isNil } from 'ramda';
import { CSSProperties, ReactNode, useRef } from 'react';
import useAI from '../../utils/hooks/useAI';
import useRichTextFieldLabels from './useRichTextFieldLabels';

interface RichTextFormikFieldProps extends FieldProps<string> {
  disabled?: boolean;
  onFocus?: (name: string) => void;
  onChange?: (name: string, value: string) => void;
  onSubmit?: (name: string, value: string) => void;
  onTextSelection?: (value: string) => void;
  required?: boolean;
  askAi?: boolean;
  label?: string;
  // Accessible name when there is no visible label (full-page editors).
  ariaLabel?: string;
  helperText?: ReactNode;
  // `height` sizes the editing area, as `height` on the design-system field.
  style?: CSSProperties;
  lastSavedValue?: string;
  hasFullScreen?: boolean;
  // Email bodies turn both off: neither renders in mail clients.
  pageBreak?: boolean;
  taskList?: boolean;
}

const RichTextFormikField = ({
  field: { name, value },
  form: { setFieldValue, setFieldTouched, errors, submitCount },
  disabled,
  onFocus,
  onChange,
  onSubmit,
  onTextSelection,
  required,
  label,
  ariaLabel,
  helperText,
  askAi,
  style,
  lastSavedValue,
  hasFullScreen = true,
  pageBreak = true,
  taskList = true,
}: RichTextFormikFieldProps) => {
  const richTextLabels = useRichTextFieldLabels();
  const [, meta] = useField(name);
  const { enabled, configured } = useAI();
  const containerRef = useRef<HTMLDivElement>(null);

  const fieldErrors = errors[name] as string | undefined;
  const showError = !isNil(meta.error) && (meta.touched || submitCount > 0);
  const unsavedChanges = lastSavedValue !== undefined && lastSavedValue !== value;
  const showAskAi = !!askAi && enabled && configured;
  // FDS-WORKAROUND #87 (fds-migration/LIBRARY-FEEDBACK.md): the Ask AI button
  // sits over the right end of the label row when there is one, otherwise over
  // the right end of the toolbar.
  const hasLabelRow = !!label || unsavedChanges;
  // Mapping: a disabled field that reports selections stays selectable, which
  // the design system calls read-only (RULE-07).
  const readOnly = !!disabled && !!onTextSelection;
  // FDS-WORKAROUND #88 (fds-migration/LIBRARY-FEEDBACK.md): in fullscreen the
  // editing area moves into a dialog outside this container, and that dialog
  // would cover the mapping drawer a selection opens. Selections made there
  // are ignored, as before the migration.
  const handleTextSelection = onTextSelection && ((text: string) => {
    if (containerRef.current?.contains(window.getSelection()?.anchorNode ?? null)) {
      onTextSelection(text);
    }
  });

  const { height, minHeight: _minHeight, ...containerStyle } = style ?? {};

  return (
    <Box
      ref={containerRef}
      sx={{
        position: 'relative',
        ...(showAskAi && {
          [hasLabelRow ? '& [role="status"]' : '& [role="toolbar"]']: { paddingRight: '32px' },
        }),
      }}
      style={containerStyle}
    >
      <RichTextField
        name={name}
        value={value ?? ''}
        onValueChange={(html) => {
          setFieldValue(name, html);
          onChange?.(name, html);
        }}
        onFocus={() => onFocus?.(name)}
        onBlur={() => {
          setFieldTouched(name, true);
          onSubmit?.(name, value);
        }}
        label={label}
        aria-label={label ? undefined : (ariaLabel ?? name)}
        required={required}
        helperText={helperText}
        error={showError && fieldErrors ? fieldErrors : undefined}
        disabled={!!disabled && !readOnly}
        readOnly={readOnly}
        onTextSelection={handleTextSelection}
        unsavedChanges={unsavedChanges}
        height={height}
        fullscreen={hasFullScreen}
        pageBreak={pageBreak}
        taskList={taskList}
        labels={richTextLabels}
      />
      {showAskAi && (
        <TextFieldAskAI
          currentValue={value ?? ''}
          setFieldValue={(val) => {
            setFieldValue(name, val);
            onSubmit?.(name, val);
          }}
          format="html"
          variant="html"
          style={{ position: 'absolute', top: hasLabelRow ? -4 : 2, right: 0 }}
          disabled={disabled}
        />
      )}
    </Box>
  );
};

export default RichTextFormikField;

import { FieldProps, useField } from 'formik';
import { InputLabel } from '@mui/material';
import MDEditor, { getExtraCommands } from '@uiw/react-md-editor/nohighlight';
import React, { CSSProperties, FocusEventHandler } from 'react';
import { useTheme } from '@mui/material/styles';
import FormHelperText from '@mui/material/FormHelperText';
import TextFieldAskAI from '@components/common/form/TextFieldAskAI';
import type { Theme } from '../../Theme';

import './MarkdownField.css';

type MarkdownFieldProps = FieldProps<string> & {
  askAi?: boolean
  disabled?: boolean
  label?: string
  onFocus?: (name: string) => void
  onSubmit?: (name: string, value: string) => void
  required?: boolean
  style?: CSSProperties
};

const MarkdownField = ({
  askAi,
  disabled,
  label,
  onFocus,
  onSubmit,
  required,
  style,
  field: { name, value },
  form: { setFieldValue, setFieldTouched, submitCount },
}: MarkdownFieldProps) => {
  const theme = useTheme<Theme>();
  const [,{ error, touched }] = useField(name);
  const showError = !!error && (touched || submitCount > 0);

  const internalOnFocus: FocusEventHandler = (event) => {
    const { nodeName } = event.relatedTarget || {};
    if (nodeName === 'INPUT' || nodeName === undefined) {
      onFocus?.(name);
    }
  };

  const internalOnBlur: FocusEventHandler = (event) => {
    const isClickOutsideCurrentField = !event.currentTarget.contains(event.relatedTarget);
    if (isClickOutsideCurrentField) {
      setFieldTouched(name, true);
      onSubmit?.(name, value || '');
    }
  };

  const extraCommands = getExtraCommands();
  if (askAi) {
    extraCommands.push({
      name: 'test',
      keyCommand: 'test',
      value: 'test',
      icon: (
        <TextFieldAskAI
          currentValue={value ?? ''}
          setFieldValue={(val) => {
            setFieldValue(name, val);
            onSubmit?.(name, val || '');
          }}
          format="markdown"
          variant="markdown"
          disabled={disabled}
        />
      ),
    });
  }

  return (
    <div
      className="octi-markdown-field"
      style={{ ...style, position: 'relative' }}
    >
      <InputLabel shrink required={required} error={showError}>
        {label}
      </InputLabel>
      <MDEditor
        onFocus={internalOnFocus}
        onBlur={internalOnBlur}
        data-color-mode={theme.palette.mode}
        value={value ?? ''}
        onChange={(val) => setFieldValue(name, val ?? '')}
        textareaProps={{ disabled }}
        extraCommands={extraCommands}
      />
      {showError && <FormHelperText error>{error}</FormHelperText>}
    </div>
  );
};

export default MarkdownField;

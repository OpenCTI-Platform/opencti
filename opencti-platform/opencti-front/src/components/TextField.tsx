import React, { ChangeEvent, ClipboardEvent, FocusEvent, KeyboardEvent, ReactNode, useCallback } from 'react';
import { TextField as MuiTextField, TextFieldProps as MuiTextFieldProps } from '@mui/material';
import { fieldToTextField } from 'formik-mui';
import { FieldProps, useField } from 'formik';
import { isNil } from 'ramda';
import TextFieldAskAI from '../private/components/common/form/TextFieldAskAI';
import StixDomainObjectDetectDuplicate from '../private/components/common/stix_domain_objects/StixDomainObjectDetectDuplicate';
import useAI from '../utils/hooks/useAI';

export type TextFieldProps = FieldProps<string> & MuiTextFieldProps & {
  detectDuplicate?: string[];
  askAi?: boolean;
  startAdornment?: ReactNode;
  onFocus?: (name: string) => void;
  onChange?: (name: string, value: string) => void;
  onSubmit?: (name: string, value: string) => void;
  onKeyDown?: (key: string) => void;
  onBeforePaste?: (value: string) => string;
};

const TextField = (props: TextFieldProps) => {
  const { detectDuplicate, onBeforePaste, startAdornment, askAi, ...htmlProps } = props;
  const {
    form: { setFieldValue, setFieldTouched, submitCount },
    field: { name },
    onChange,
    onFocus,
    onSubmit,
    onKeyDown,
  } = props;
  const { fullyActive } = useAI();

  const internalOnChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const { value } = event.target;
    setFieldValue(name, value);
    if (typeof onChange === 'function') {
      onChange(name, value);
    }
  }, [onChange, setFieldValue, name]);

  const internalOnFocus = useCallback(() => {
    if (typeof onFocus === 'function') {
      onFocus(name);
    }
  }, [onFocus, name]);

  const internalOnBlur = useCallback((event: FocusEvent<HTMLInputElement>) => {
    const { value } = event.target;
    setFieldTouched(name, true);
    if (typeof onSubmit === 'function') {
      onSubmit(name, value || '');
    }
  }, [onSubmit, setFieldTouched, name]);

  const internalOnPaste = useCallback((event: ClipboardEvent<HTMLInputElement>) => {
    // onBeforePaste can be used to alter the pasted content
    // this works for textarea or input
    if (typeof onBeforePaste === 'function') {
      event.preventDefault(); // prevent default paste
      // alter the pasted content according to onBeforePaste result
      const pastedText = event.clipboardData.getData('text/plain');
      // remove \r character to only work with strings using \n (for cursor computation)
      const sanitizedPastedText = pastedText.replace(/\r/g, '');
      const newPastedText = onBeforePaste(sanitizedPastedText);
      // Insert the modified text at the current cursor position
      const input = event.target as HTMLInputElement;
      const start = input.selectionStart;
      const end = input.selectionEnd;
      if (start !== null && end !== null) {
        const before = input.value.slice(0, start);
        const after = input.value.slice(end);
        input.value = before + newPastedText + after;
        // Set the cursor position after the inserted text
        const cursorPosition = start + newPastedText.length;
        input.setSelectionRange(cursorPosition, cursorPosition);
      }

      setFieldValue(name, input.value);
    }
  }, [onBeforePaste, setFieldValue, name]);

  const internalOnKeyDown = useCallback((event: KeyboardEvent<HTMLInputElement>) => {
    const { key } = event;
    if (onKeyDown) {
      onKeyDown(key);
      return;
    }

    if (key === 'Enter' && onSubmit) {
      const { value } = props.field;
      onSubmit(name, value ?? '');
    }
  }, [onKeyDown, onSubmit, name]);

  const [, meta] = useField(name);
  const { value, ...otherProps } = fieldToTextField(htmlProps);

  const showError = !isNil(meta.error) && (meta.touched || submitCount > 0);

  return (
    <MuiTextField
      {...otherProps}
      value={value ?? ''}
      error={showError}
      helperText={

        detectDuplicate && !showError ? (
          <StixDomainObjectDetectDuplicate
            types={detectDuplicate}
            value={meta.value}
          />
        ) : showError ? (
          meta.error
        ) : (
          props.helperText
        )
      }
      onChange={internalOnChange}
      onFocus={internalOnFocus}
      onBlur={internalOnBlur}
      onPaste={internalOnPaste}
      onKeyDown={internalOnKeyDown}
      slotProps={{
        input: {
          startAdornment,
          endAdornment: askAi && fullyActive && (
            <TextFieldAskAI
              currentValue={value as string ?? ''}
              setFieldValue={(val) => {
                setFieldValue(name, val);
                if (typeof onSubmit === 'function') {
                  onSubmit(name, val || '');
                }
              }}
              format="text"
              disabled={props.disabled}
            />
          ),
        },
      }}
    />
  );
};

export default TextField;

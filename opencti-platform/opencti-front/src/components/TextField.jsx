import React from 'react';
import MuiTextField from '@mui/material/TextField';
import { fieldToTextField } from 'formik-mui';
import { useField } from 'formik';
import { isNil } from 'ramda';
import TextFieldAskAI from '../private/components/common/form/TextFieldAskAI';
import StixDomainObjectDetectDuplicate from '../private/components/common/stix_domain_objects/StixDomainObjectDetectDuplicate';

const TextField = (props) => {
  const { detectDuplicate, onBeforePaste, startAdornment, ...htmlProps } = props;
  const {
    form: { setFieldValue, setFieldTouched },
    field: { name },
    onChange,
    onFocus,
    onSubmit,
    askAi,
  } = props;
  const internalOnChange = React.useCallback(
    (event) => {
      const { value } = event.target;
      setFieldValue(name, value);
      if (typeof onChange === 'function') {
        onChange(name, value);
      }
    },
    [onChange, setFieldValue, name],
  );
  const internalOnFocus = React.useCallback(() => {
    if (typeof onFocus === 'function') {
      onFocus(name);
    }
  }, [onFocus, name]);
  const internalOnBlur = React.useCallback(
    (event) => {
      const { value } = event.target;
      setFieldTouched(name, true);
      if (typeof onSubmit === 'function') {
        onSubmit(name, value || '');
      }
    },
    [onSubmit, setFieldTouched, name],
  );
  const internalOnPaste = React.useCallback(
    (event) => {
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
        const input = event.target;
        const start = input.selectionStart;
        const end = input.selectionEnd;
        const before = input.value.slice(0, start);
        const after = input.value.slice(end);
        input.value = before + newPastedText + after;
        // Set the cursor position after the inserted text
        const cursorPosition = start + newPastedText.length;
        input.setSelectionRange(cursorPosition, cursorPosition);

        setFieldValue(name, input.value);
      }
    },
    [onBeforePaste, setFieldValue, name],
  );
  const [, meta] = useField(name);
  const { value, ...otherProps } = fieldToTextField(htmlProps);
  return (
    <MuiTextField
      {...otherProps}
      value={value ?? ''}
      error={!isNil(meta.error) || otherProps.error}
      helperText={
        // eslint-disable-next-line no-nested-ternary
          detectDuplicate && (isNil(meta.error) || !meta.touched) ? (
            <StixDomainObjectDetectDuplicate
              types={detectDuplicate}
              value={meta.value}
            />
          ) : meta.error ? (
            meta.error
          ) : (
            props.helperText
          )
      }
      onChange={internalOnChange}
      onFocus={internalOnFocus}
      onBlur={internalOnBlur}
      onPaste={internalOnPaste}
      InputProps={{
        startAdornment,
        endAdornment: askAi && (
          <TextFieldAskAI
            currentValue={value}
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
      }}
    />
  );
};

export default TextField;

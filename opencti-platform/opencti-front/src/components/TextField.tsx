import React, { BaseSyntheticEvent, FunctionComponent } from 'react';
import MuiTextField from '@mui/material/TextField';
import { fieldToTextField, type TextFieldProps } from 'formik-mui';
import { isNil } from 'ramda';
import { TextFieldProps as MuiTextFieldProps } from '@mui/material/TextField/TextField';
import { useField } from 'formik';
import StixDomainObjectDetectDuplicate from '../private/components/common/stix_domain_objects/StixDomainObjectDetectDuplicate';

interface CustomProps {
  detectDuplicate?: string[];
}

interface ExtendedTextFieldProps extends TextFieldProps, CustomProps {}

const TextField: FunctionComponent<ExtendedTextFieldProps> = (
  props,
) => {
  const {
    form: { setFieldValue, setFieldTouched },
    field: { name, onChange, onBlur },
    onFocus,
    detectDuplicate,
  } = props;

  const [, meta] = useField(name);

  const internalOnChange = React.useCallback(
    async (event: BaseSyntheticEvent) => {
      const { value } = event.target;
      await setFieldValue(name, value);
      if (typeof onChange === 'function') {
        onChange(name);
      }
    },
    [onChange, setFieldValue, name],
  );
  const internalOnFocus = React.useCallback(async (event: BaseSyntheticEvent) => {
    const { value } = event.target;
    await setFieldValue(name, value);
    if (typeof onFocus === 'function') {
      onFocus(value);
    }
  }, [onFocus, name]);
  const internalOnBlur = React.useCallback(
    async () => {
      await setFieldTouched(name, true);
      if (typeof onBlur === 'function') {
        onBlur(name);
      }
    },
    [onBlur, setFieldTouched, name],
  );

  const { value, ...otherProps }:MuiTextFieldProps = fieldToTextField(props);

  return (
    <MuiTextField
      {...otherProps}
      value={value ?? ''}
      error={!isNil(meta.error) && meta.touched}
      helperText={
        (meta.value && meta.value.length > 2 && detectDuplicate) ? (
          <StixDomainObjectDetectDuplicate
            types={detectDuplicate}
            value={value as string}
          />
        ) : meta.error
      }
      onChange={internalOnChange}
      onFocus={internalOnFocus}
      onBlur={internalOnBlur}
    />
  );
};

export default TextField;

import React from 'react';
import MuiTextField from '@mui/material/TextField';
import { fieldToTextField } from 'formik-mui';
import { useField } from 'formik';
import { isNil } from 'ramda';
import TextFieldAskAI from '@components/common/form/TextFieldAskAI';
import InputAdornment from '@mui/material/InputAdornment';
import { Search } from '@mui/icons-material';
import StixDomainObjectDetectDuplicate from '../private/components/common/stix_domain_objects/StixDomainObjectDetectDuplicate';

const TextField = (props) => {
  const {
    form: { setFieldValue, setTouched },
    field: { name },
    onChange,
    onFocus,
    onSubmit,
    detectDuplicate,
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
      setTouched(true);
      if (typeof onSubmit === 'function') {
        onSubmit(name, value || '');
      }
    },
    [onSubmit, setTouched, name],
  );
  const [, meta] = useField(name);
  const { value, ...otherProps } = fieldToTextField(props);
  return (
    <MuiTextField
      {...otherProps}
      value={value ?? ''}
      error={!isNil(meta.error)}
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
      InputProps={{
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
          />
        ),
      }}
    />
  );
};

export default TextField;

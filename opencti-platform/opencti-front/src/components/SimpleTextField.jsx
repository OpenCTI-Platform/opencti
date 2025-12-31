import React from 'react';
import MuiTextField from '@mui/material/TextField';
import { fieldToTextField } from 'formik-mui';
import { useField } from 'formik';
import { isNil } from 'ramda';
import StixDomainObjectDetectDuplicate from '../private/components/common/stix_domain_objects/StixDomainObjectDetectDuplicate';

const TextField = (props) => {
  const {
    form: { setFieldValue, setFieldTouched, submitCount },
    field: { name },
    onChange,
    onFocus,
    onSubmit,
    detectDuplicate,
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
  const [, meta] = useField(name);
  const { value, ...otherProps } = fieldToTextField(props);
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
    />
  );
};

export default TextField;

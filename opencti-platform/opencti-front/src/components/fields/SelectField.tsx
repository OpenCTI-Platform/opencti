import React from 'react';
import { isNil } from 'ramda';
import { FieldProps, getIn, useField } from 'formik';
import { v4 as uuid } from 'uuid';
import MuiSelect from '@mui/material/Select';
import InputLabel from '@mui/material/InputLabel';
import FormControl from '@mui/material/FormControl';
import FormHelperText from '@mui/material/FormHelperText';
import { SelectProps } from '@mui/material';

export type SelectFieldProps = FieldProps<string> & Omit<SelectProps<string>, 'onChange' | 'onFocus'> & {
  required: boolean;
  onChange?: (name: string, value: string) => void;
  onFocus?: (name: string) => void;
  onSubmit?: (name: string, value: string) => void;
  containerstyle?: Record<string, string | number>;
  helpertext?: string;
};

const fieldToSelect = (muiProps: SelectFieldProps) => {
  const {
    disabled,
    field: { onChange: fieldOnChange, ...field },
    form: { isSubmitting, touched, errors, setFieldTouched, setFieldValue },
    onClose,
  } = muiProps;
  const fieldError = getIn(errors, field.name);
  const showError = getIn(touched, field.name) && !!fieldError;

  return {
    ...field,
    ...muiProps,
    disabled: disabled ?? isSubmitting,
    error: showError,
    onBlur: () => {},
    onChange: fieldOnChange ?? (() => {}),
    onClose: onClose ?? (async (e) => {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      const { dataset } = e.target;
      if (dataset && dataset.value) {
        await setFieldValue(field.name, dataset.value);
      }
      setFieldTouched(field.name, true);
    }),
  };
};

const SelectField = (muiProps: SelectFieldProps) => {
  const {
    form: { setFieldValue, setFieldTouched },
    field: { name },
    required = false,
    onChange,
    onFocus,
    onSubmit,
    containerstyle,
    helpertext,
  } = muiProps;

  const internalOnChange = React.useCallback<NonNullable<SelectProps<string>['onChange']>>(
    (event) => {
      const { value } = event.target;
      setFieldValue(name, value);
      if (typeof onChange === 'function') {
        onChange(name, value);
      }
    },
    [setFieldValue, onChange, name],
  );
  const internalOnFocus = React.useCallback<NonNullable<SelectProps<string>['onFocus']>>(() => {
    if (typeof onFocus === 'function') {
      onFocus(name);
    }
  }, [onFocus, name]);
  const internalOnBlur = React.useCallback<NonNullable<SelectProps<string>['onBlur']>>(
    (event) => {
      const { value } = event.target;
      setFieldTouched(name, true);
      if (typeof onSubmit === 'function') {
        onSubmit(name, value || '');
      }
    },
    [setFieldTouched, onSubmit, name],
  );
  const [, meta] = useField(name);
  const { value, ...otherProps } = fieldToSelect(muiProps);

  const labelId = uuid();

  return (
    <FormControl
      style={containerstyle}
      error={meta.touched && !isNil(meta.error)}
    >
      <InputLabel
        style={{ color: muiProps.disabled ? '#4f4f4f' : '' }}
        variant={muiProps.variant}
        id={labelId}
        required={required}
      >
        {muiProps.label}
      </InputLabel>
      <MuiSelect
        {...otherProps}
        value={value ?? ''}
        onChange={internalOnChange}
        onFocus={internalOnFocus}
        onBlur={internalOnBlur}
        labelId={labelId}
      />
      <FormHelperText
        variant={muiProps.variant}
        style={{
          display:
            (meta.touched && !isNil(meta.error))
            || (isNil(meta.error) && helpertext)
              ? 'block'
              : 'none',
        }}
      >
        {meta.touched && !isNil(meta.error) ? meta.error : helpertext}
      </FormHelperText>
    </FormControl>
  );
};

export default SelectField;

import React from 'react';
import { isNil } from 'ramda';
import { getIn, useField } from 'formik';
import { v4 as uuid } from 'uuid';
import MuiSelect from '@mui/material/Select';
import InputLabel from '@mui/material/InputLabel';
import FormControl from '@mui/material/FormControl';
import FormHelperText from '@mui/material/FormHelperText';

const fieldToSelect = ({
  disabled,
  field: { onChange: fieldOnChange, ...field },
  form: { isSubmitting, touched, errors, setFieldTouched, setFieldValue },
  onClose,
  ...props
}) => {
  const fieldError = getIn(errors, field.name);
  const showError = getIn(touched, field.name) && !!fieldError;
  return {
    disabled: disabled ?? isSubmitting,
    error: showError,
    onBlur: () => {},
    onChange: fieldOnChange ?? (() => {}),
    onClose: onClose ?? (async (e) => {
      const { dataset } = e.target;
      if (dataset && dataset.value) {
        await setFieldValue(field.name, dataset.value);
      }
      setFieldTouched(field.name, true);
    }),
    ...field,
    ...props,
  };
};

const SelectField = (props) => {
  const {
    form: { setFieldValue, setFieldTouched },
    field: { name },
    onChange,
    onFocus,
    onSubmit,
  } = props;
  const internalOnChange = React.useCallback(
    (event) => {
      const { value } = event.target;
      setFieldValue(name, value);
      if (typeof onChange === 'function') {
        onChange(name, value);
      }
    },
    [setFieldValue, onChange, name],
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
    [setFieldTouched, onSubmit, name],
  );
  const [, meta] = useField(name);
  const { value, ...otherProps } = fieldToSelect(props);

  const labelId = uuid();

  return (
    <FormControl
      style={props.containerstyle}
      error={meta.touched && !isNil(meta.error)}
    >
      <InputLabel
        style={{ color: props.disabled ? '#4f4f4f' : '' }}
        variant={props.variant}
        id={labelId}
        required
      >
        {props.label}
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
        variant={props.variant}
        style={{
          display:
            (meta.touched && !isNil(meta.error))
            || (isNil(meta.error) && props.helpertext)
              ? 'block'
              : 'none',
        }}
      >
        {meta.touched && !isNil(meta.error) ? meta.error : props.helpertext}
      </FormHelperText>
    </FormControl>
  );
};

export default SelectField;

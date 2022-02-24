import React from 'react';
import { isNil } from 'ramda';
import { useField } from 'formik';
import MuiSelect from '@mui/material/Select';
import InputLabel from '@mui/material/InputLabel';
import FormControl from '@mui/material/FormControl';
import FormHelperText from '@mui/material/FormHelperText';
import { fieldToSelect } from 'formik-mui';

const SelectField = (props) => {
  const {
    form: { setFieldValue, setTouched },
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
      setTouched(true);
      if (typeof onSubmit === 'function') {
        onSubmit(name, value || '');
      }
    },
    [setTouched, onSubmit, name],
  );
  const [, meta] = useField(name);
  return (
    <FormControl
      style={props.containerstyle}
      error={meta.touched && !isNil(meta.error)}
    >
      <InputLabel
        style={{ color: props.disabled ? '#4f4f4f' : '' }}
        variant={props.variant}
      >
        {props.label}
      </InputLabel>
      <MuiSelect
        {...fieldToSelect(props)}
        onChange={internalOnChange}
        onFocus={internalOnFocus}
        onBlur={internalOnBlur}
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

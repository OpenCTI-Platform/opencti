import React from 'react';
import { isNil } from 'ramda';
import { useField } from 'formik';
import MuiSelect from '@material-ui/core/Select';
import InputLabel from '@material-ui/core/InputLabel';
import FormControl from '@material-ui/core/FormControl';
import FormHelperText from '@material-ui/core/FormHelperText';
import { fieldToSelect } from 'formik-material-ui';

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
      <InputLabel style={{ color: props.disabled ? '#4f4f4f' : '' }}>
        {props.label}
      </InputLabel>
      <MuiSelect
        {...fieldToSelect(props)}
        onChange={internalOnChange}
        onFocus={internalOnFocus}
        onBlur={internalOnBlur}
      />
      <FormHelperText
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

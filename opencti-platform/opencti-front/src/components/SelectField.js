import React from 'react';
import { isNil } from 'ramda';
import { useField } from 'formik';
import MuiSelect from '@material-ui/core/Select';
import InputLabel from '@material-ui/core/InputLabel';
import FormControl from '@material-ui/core/FormControl';
import FormHelperText from '@material-ui/core/FormHelperText';
import { useFieldToSelect } from 'formik-material-ui';

const SelectField = (props) => {
  const [, meta] = useField(props);
  const customize = React.useCallback(
    ([field, , helpers]) => ({
      onChange: (event) => {
        const { value } = event.target;
        helpers.setValue(value);
        if (typeof props.onChange === 'function') {
          props.onChange(field.name, value);
        }
      },
      onFocus: () => {
        if (typeof props.onFocus === 'function') {
          props.onFocus(field.name);
        }
      },
      onBlur: (event) => {
        helpers.setTouched(true);
        if (typeof props.onSubmit === 'function') {
          props.onSubmit(field.name, event.target.value);
        }
      },
    }),
    [props],
  );
  return (
    <FormControl
      style={props.containerstyle}
      error={meta.touched && !isNil(meta.error)}
    >
      <InputLabel style={{ color: props.disabled ? '#4f4f4f' : '' }}>
        {props.label}
      </InputLabel>
      <MuiSelect {...useFieldToSelect(props, customize)} />
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

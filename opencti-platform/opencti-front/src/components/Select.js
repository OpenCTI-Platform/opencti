import React from 'react';
import MuiSelect from '@material-ui/core/Select';
import InputLabel from '@material-ui/core/InputLabel';
import FormControl from '@material-ui/core/FormControl';
import FormHelperText from '@material-ui/core/FormHelperText';
import { useField } from 'formik';
import { useFieldToSelect } from 'formik-material-ui';

const Select = (props) => {
  const fieldProps = useFieldToSelect(props);
  const [, meta, helpers] = useField(props.name);
  return (
    <FormControl
      style={props.containerstyle}
      error={meta.error !== undefined && meta.touched}
    >
      <InputLabel style={{ color: props.disabled ? '#4f4f4f' : '' }}>
        {props.label}
      </InputLabel>
      <MuiSelect
        {...fieldProps}
        onChange={(event) => {
          const { value } = event.target;
          helpers.setValue(value);
          if (typeof props.onChange === 'function') {
            props.onChange(props.field.name, value);
          }
        }}
        onFocus={() => {
          if (typeof props.onFocus === 'function') {
            props.onFocus(props.field.name);
          }
        }}
        classes={props.classes}
        className={props.className}
      />
      {props.helpertext && meta.error === undefined ? (
        <FormHelperText>{props.helpertext}</FormHelperText>
      ) : (
        ''
      )}
      {meta.error !== undefined && meta.touched ? (
        <FormHelperText>{props.form.errors[props.field.name]}</FormHelperText>
      ) : (
        ''
      )}
    </FormControl>
  );
};

export default Select;

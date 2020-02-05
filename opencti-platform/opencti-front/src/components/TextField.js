import React from 'react';
import MuiTextField from '@material-ui/core/TextField';
import { useField } from 'formik';
import { useFieldToTextField } from 'formik-material-ui';

const TextField = (props) => {
  const fieldProps = useFieldToTextField(props);
  const [, , helpers] = useField(props.name);
  return (
    <MuiTextField
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
      onKeyPress={(event) => {
        helpers.setTouched(true);
        if (typeof props.onSubmit === 'function' && event.key === 'Enter') {
          props.onSubmit(props.field.name, event.target.value);
        }
      }}
      onBlur={(event) => {
        helpers.setTouched(true);
        if (typeof props.onSubmit === 'function') {
          props.onSubmit(props.field.name, event.target.value);
        }
      }}
      classes={props.classes}
      className={props.className}
    />
  );
};

export default TextField;

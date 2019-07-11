import React from 'react';
import MuiTextField from '@material-ui/core/TextField';
import { fieldToTextField } from 'formik-material-ui';

const TextField = props => (
  <MuiTextField
    {...fieldToTextField(props)}
    onChange={(event) => {
      const { value } = event.target;
      props.form.setFieldValue(props.field.name, value);
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
      props.form.setFieldTouched(props.field.name, true, true);
      if (typeof props.onSubmit === 'function' && event.key === 'Enter') {
        props.onSubmit(props.field.name, event.target.value);
      }
    }}
    onBlur={(event) => {
      props.form.setFieldTouched(props.field.name, true, true);
      if (typeof props.onSubmit === 'function') {
        props.onSubmit(props.field.name, event.target.value);
      }
    }}
    classes={props.classes}
    className={props.className}
  />
);

export default TextField;

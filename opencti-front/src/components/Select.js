import React from 'react';
import MuiSelect from '@material-ui/core/Select';
import InputLabel from '@material-ui/core/InputLabel';
import FormControl from '@material-ui/core/FormControl';
import { fieldToSelect } from 'formik-material-ui';

const Select = props => (
  <FormControl style={props.containerstyle}>
    <InputLabel shrink htmlFor="age-label-placeholder">
      {props.label}
    </InputLabel>
  <MuiSelect
    {...fieldToSelect(props)}
    onChange={(event) => {
      const { value } = event.target;
      props.form.setFieldValue(
        props.field.name,
        value,
      );
      if (typeof props.onChange === 'function') {
        props.onChange(props.field.name, value);
      }
    }}
    classes={props.classes}
    className={props.className}
  />
  </FormControl>
);

export default Select;

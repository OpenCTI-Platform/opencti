import React from 'react';
import MuiSelect from '@material-ui/core/Select';
import InputLabel from '@material-ui/core/InputLabel';
import FormControl from '@material-ui/core/FormControl';
import FormHelperText from '@material-ui/core/FormHelperText';
import { fieldToSelect } from 'formik-material-ui';

const Select = props => (
  <FormControl style={props.containerstyle} error={props.form.errors[props.field.name] !== undefined}>
    <InputLabel>
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
      onFocus={() => {
        console.log(props);
        if (typeof props.onFocus === 'function') {
          props.onFocus(props.field.name);
        }
      }}
      classes={props.classes}
      className={props.className}
    />
    {props.helpertext && props.form.errors[props.field.name] === undefined ? <FormHelperText>{props.helpertext}</FormHelperText> : ''}
    {props.form.errors[props.field.name] !== undefined ? <FormHelperText>{props.form.errors[props.field.name]}</FormHelperText> : ''}
  </FormControl>
);

export default Select;

import React from 'react';
import MuiSelect from '@material-ui/core/Select';
import InputLabel from '@material-ui/core/InputLabel';
import FormControl from '@material-ui/core/FormControl';
import FormHelperText from '@material-ui/core/FormHelperText';
import { fieldToSelect } from 'formik-material-ui';

const Select = props => (
  <FormControl style={props.containerstyle}>
    <InputLabel shrink={true}>
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
        if (typeof props.onFocus === 'function') {
          props.onFocus(props.field.name);
        }
      }}
      classes={props.classes}
      className={props.className}
    />
    {props.helpertext ? <FormHelperText>{props.helpertext}</FormHelperText> : ''}
  </FormControl>
);

export default Select;

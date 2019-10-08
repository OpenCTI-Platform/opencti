import React from 'react';
import MuiSwitch from '@material-ui/core/Switch';
import FormControlLabel from '@material-ui/core/FormControlLabel';
import { fieldToSwitch } from 'formik-material-ui';

const Switch = (props) => (
  <div style={props.containerstyle}>
    <FormControlLabel
      control={
        <MuiSwitch
          {...fieldToSwitch(props)}
          onChange={(event) => {
            const value = event.target.checked ? 'true' : 'false';
            props.form.setFieldValue(props.field.name, event.target.checked);
            if (typeof props.onChange === 'function') {
              props.onChange(props.field.name, value);
            }
          }}
        />
      }
      label={props.label}
    />
  </div>
);

export default Switch;

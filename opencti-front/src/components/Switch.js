import React from 'react';
import MuiSwitch from '@material-ui/core/Switch';
import FormControlLabel from '@material-ui/core/FormControlLabel';
import { fieldToSwitch } from 'formik-material-ui';

const Switch = props => (
  <div style={props.containerstyle}>
    <FormControlLabel
      control={<MuiSwitch {...fieldToSwitch(props)}/>}
      label={props.label}
    />
  </div>
);

export default Switch;

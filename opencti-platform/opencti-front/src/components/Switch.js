import React from 'react';
import MuiSwitch from '@material-ui/core/Switch';
import FormControlLabel from '@material-ui/core/FormControlLabel';
import { useField } from 'formik';
import { useFieldToSwitch } from 'formik-material-ui';

const Switch = (props) => {
  const fieldProps = useFieldToSwitch(props);
  const [, , helpers] = useField(props.name);
  return (
    <div style={props.containerstyle}>
      <FormControlLabel
        control={
          <MuiSwitch
            {...fieldProps}
            onChange={(event) => {
              const value = event.target.checked ? 'true' : 'false';
              helpers.setValue(event.target.checked);
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
};

export default Switch;

import React from 'react';
import MuiSwitch from '@material-ui/core/Switch';
import FormControlLabel from '@material-ui/core/FormControlLabel';
import { useFieldToSwitch } from 'formik-material-ui';

const SwitchField = (props) => {
  const customize = React.useCallback(
    ([field, , helpers]) => ({
      onChange: (event) => {
        const value = event.target.checked ? 'true' : 'false';
        helpers.setValue(event.target.checked);
        if (typeof props.onChange === 'function') {
          props.onChange(field.name, value);
        }
      },
    }),
    [props],
  );
  return (
    <div style={props.containerstyle}>
      <FormControlLabel
        control={<MuiSwitch {...useFieldToSwitch(props, customize)} />}
        label={props.label}
      />
    </div>
  );
};

export default SwitchField;

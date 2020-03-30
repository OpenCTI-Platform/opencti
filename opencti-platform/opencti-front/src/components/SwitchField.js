import React from 'react';
import MuiSwitch from '@material-ui/core/Switch';
import FormControlLabel from '@material-ui/core/FormControlLabel';
import { fieldToSwitch } from 'formik-material-ui';

const SwitchField = (props) => {
  const {
    form: { setFieldValue },
    field: { name },
    onChange,
  } = props;
  const internalOnChange = React.useCallback(
    (event) => {
      const value = event.target.checked ? 'true' : 'false';
      setFieldValue(name, event.target.checked);
      if (typeof onChange === 'function') {
        onChange(name, value);
      }
    },
    [onChange, setFieldValue, name],
  );
  return (
    <div style={props.containerstyle}>
      <FormControlLabel
        control={
          <MuiSwitch {...fieldToSwitch(props)} onChange={internalOnChange} />
        }
        label={props.label}
      />
    </div>
  );
};

export default SwitchField;

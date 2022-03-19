import React from 'react';
import MuiSwitch from '@mui/material/Switch';
import FormControlLabel from '@mui/material/FormControlLabel';
import FormGroup from '@mui/material/FormGroup';
import FormHelperText from '@mui/material/FormHelperText';
import { fieldToSwitch } from 'formik-mui';

const SwitchField = (props) => {
  const {
    form: { setFieldValue, setTouched },
    field: { name },
    onChange,
    helpertext,
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
  const internalOnBlur = React.useCallback(() => {
    setTouched(true);
  }, [setTouched]);
  return (
    <div style={props.containerstyle}>
      <FormGroup>
        <FormControlLabel
          control={
            <MuiSwitch
              {...fieldToSwitch(props)}
              onChange={internalOnChange}
              onBlur={internalOnBlur}
            />
          }
          label={props.label}
        />
      </FormGroup>
      <FormHelperText>{helpertext}</FormHelperText>
    </div>
  );
};

export default SwitchField;

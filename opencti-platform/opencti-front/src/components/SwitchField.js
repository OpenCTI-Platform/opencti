import React from 'react';
import { compose } from 'ramda';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import MuiSwitch from '@material-ui/core/Switch';
import FormControlLabel from '@material-ui/core/FormControlLabel';
import FormGroup from '@material-ui/core/FormGroup';
import FormHelperText from '@material-ui/core/FormHelperText';
import { fieldToSwitch } from 'formik-material-ui';

const styles = () => ({
  switch_track: {
    backgroundColor: '#D3134A',
    opacity: 1,
  },
  switch_base: {
    color: 'white',
    '&.Mui-checked': {
      color: '#49B8FC',
    },
    '&.Mui-checked + .MuiSwitch-track': {
      backgroundColor: '#49B8FC',
      opacity: 1,
    },
  },
  switch_primary: {
    '&.Mui-checked': {
      color: 'white',
    },
    '&.Mui-checked + .MuiSwitch-track': {
      backgroundColor: '#49B8FC',
    },
  },
});

const SwitchField = (props) => {
  const {
    form: { setFieldValue, setTouched },
    field: { name },
    onChange,
    helpertext,
    classes,
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
              color='primary'
              classes={{
                track: classes.switch_track,
                switchBase: classes.switch_base,
                colorPrimary: classes.switch_primary,
              }}
            />
          }
          label={props.label}
        />
      </FormGroup>
      <FormHelperText>{helpertext}</FormHelperText>
    </div>
  );
};

SwitchField.propTypes = {
  classes: PropTypes.object,
};

export default compose(withStyles(styles))(SwitchField);

import React, { useCallback, useEffect } from 'react';
import MuiSwitch from '@mui/material/Switch';
import FormControlLabel from '@mui/material/FormControlLabel';
import FormGroup from '@mui/material/FormGroup';
import FormHelperText from '@mui/material/FormHelperText';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import { fieldToSwitch } from 'formik-mui';
import { useFormatter } from '../i18n';

const SwitchField = (props) => {
  const {
    form: { setFieldValue, setFieldTouched },
    field: { name },
    onChange,
    helpertext,
    tooltip,
    initialValue,
  } = props;
  const { t_i18n } = useFormatter();
  const internalOnChange = useCallback(
    (event) => {
      const value = event.target.checked ? 'true' : 'false';
      setFieldValue(name, event.target.checked);
      if (typeof onChange === 'function') {
        onChange(name, value);
      }
    },
    [onChange, setFieldValue, name],
  );
  const internalOnBlur = useCallback(() => {
    setFieldTouched(name, true);
  }, [setFieldTouched]);

  useEffect(() => {
    if (initialValue !== undefined) {
      setFieldValue(name, initialValue);
      if (typeof onChange === 'function') {
        onChange(name, initialValue ? 'true' : 'false');
      }
    }
  }, []);

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
          label={
            tooltip ? (
              <div style={{ display: 'flex' }}>
                <span>{props.label}</span>
                <Tooltip
                  title={t_i18n(tooltip)}
                >
                  <InformationOutline
                    fontSize="small"
                    color="primary"
                    style={{ cursor: 'default', margin: '0 0 0 10px' }}
                  />
                </Tooltip>
              </div>
            ) : (
              props.label
            )
          }
        />
      </FormGroup>
      <FormHelperText>{helpertext}</FormHelperText>
    </div>
  );
};

export default SwitchField;

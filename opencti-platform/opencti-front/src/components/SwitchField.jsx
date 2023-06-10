import React, { useCallback } from 'react';
import MuiSwitch from '@mui/material/Switch';
import FormControlLabel from '@mui/material/FormControlLabel';
import FormGroup from '@mui/material/FormGroup';
import FormHelperText from '@mui/material/FormHelperText';
import { fieldToSwitch } from 'formik-mui';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import { useFormatter } from './i18n';

const SwitchField = (props) => {
  const {
    form: { setFieldValue, setTouched },
    field: { name },
    onChange,
    helpertext,
    tooltip,
  } = props;
  const { t } = useFormatter();
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
          label={
            tooltip ? (
              <div style={{ display: 'flex' }}>
                <span>{props.label}</span>
                <Tooltip
                  title={t(
                    'All objects matching the filters that have not been updated since this amount of days will be deleted',
                  )}
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

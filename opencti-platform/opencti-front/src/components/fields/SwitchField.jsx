import React, { useCallback, useEffect } from 'react';
import { Switch } from '@filigran/design-system';
import FormGroup from '@mui/material/FormGroup';
import FormHelperText from '@mui/material/FormHelperText';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import { useFormatter } from '../i18n';

const SwitchField = (props) => {
  const {
    form: { setFieldValue, setFieldTouched },
    field: { name, value },
    onChange,
    helpertext,
    tooltip,
    initialValue,
    disabled,
    required,
    label,
  } = props;
  const { t_i18n } = useFormatter();
  // Radix reports the new value directly; MUI reported an event whose
  // target.checked had to be read. The string form is kept because consumers
  // of `onChange` receive 'true'/'false', not a boolean.
  const internalOnChange = useCallback(
    (checked) => {
      setFieldValue(name, checked);
      if (typeof onChange === 'function') {
        onChange(name, checked ? 'true' : 'false');
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

  const labelNode = tooltip ? (
    <div style={{ display: 'flex' }}>
      <span>{label}</span>
      <Tooltip title={t_i18n(tooltip)}>
        <InformationOutline
          fontSize="small"
          color="primary"
          style={{ cursor: 'default', margin: '0 0 0 10px' }}
        />
      </Tooltip>
    </div>
  ) : (
    label
  );

  return (
    <div style={props.containerstyle}>
      {/* FormGroup and the fit-content wrapper are kept so the control keeps
          the row position it had under MUI; the library Switch carries its own
          label, so FormControlLabel is gone — it clone-injects checked/onChange
          into its control, which a Radix button would silently ignore. */}
      <FormGroup>
        <div style={{ width: 'fit-content' }}>
          <Switch
            name={name}
            checked={value === true}
            disabled={disabled}
            required={required}
            label={labelNode}
            onCheckedChange={internalOnChange}
            onBlur={internalOnBlur}
          />
        </div>
      </FormGroup>
      <FormHelperText>{helpertext}</FormHelperText>
    </div>
  );
};

export default SwitchField;

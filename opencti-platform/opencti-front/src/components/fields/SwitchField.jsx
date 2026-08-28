import React, { useCallback, useEffect } from 'react';
import { Switch } from '@filigran/design-system';
import FormGroup from '@mui/material/FormGroup';
import FormHelperText from '@mui/material/FormHelperText';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import { useFormatter } from '../i18n';

const SwitchField = (props) => {
  const {
    form: { setFieldValue, setFieldTouched, isSubmitting },
    field: { name, value },
    onChange,
    onFocus,
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
          the row position it had under MUI. FormControlLabel is gone because
          the library Switch carries its own label — NOT because this file was
          exposed to the clone-injection trap: the old code put checked and
          onChange on the MuiSwitch child, so FormControlLabel had nothing to
          inject. The mechanism is real (it broke the consent checkbox in
          #17946); it simply was not active here. */}
      <FormGroup>
        <div style={{ width: 'fit-content' }}>
          <Switch
            name={name}
            // A caller-supplied `checked` wins over the Formik value: three
            // sites drive the control from their own state, and one of them
            // (TriggerEditionOverview) keeps its value outside Formik.
            checked={props.checked ?? value === true}
            // formik-mui's fieldToSwitch supplied this; without it the 107
            // switches stayed live during submit.
            disabled={disabled ?? isSubmitting}
            required={required}
            label={labelNode}
            onCheckedChange={internalOnChange}
            onFocus={onFocus}
            onBlur={internalOnBlur}
          />
        </div>
      </FormGroup>
      <FormHelperText>{helpertext}</FormHelperText>
    </div>
  );
};

export default SwitchField;

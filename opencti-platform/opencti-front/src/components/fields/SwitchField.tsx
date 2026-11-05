import React, { CSSProperties, ReactNode, useCallback, useEffect } from 'react';
import { Switch, SwitchProps, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import FormGroup from '@mui/material/FormGroup';
import FormHelperText from '@mui/material/FormHelperText';
import { InformationOutline } from 'mdi-material-ui';
import { FieldProps } from 'formik';
import { useFormatter } from '../i18n';

export type SwitchFieldProps = FieldProps<boolean | undefined> & {
  label?: ReactNode;
  // Translated here: callers pass the English text
  tooltip?: string;
  helpertext?: ReactNode;
  // Written into Formik once, when the field mounts
  initialValue?: boolean;
  // A caller-supplied value wins over the Formik one
  checked?: boolean;
  disabled?: boolean;
  required?: boolean;
  containerstyle?: CSSProperties;
  // Receives the new value as a string, as the MUI switch reported it
  onChange?: (name: string, value: string) => void;
  onFocus?: SwitchProps['onFocus'];
};

const SwitchField = ({
  form: { setFieldValue, setFieldTouched, isSubmitting },
  field: { name, value },
  label,
  tooltip,
  helpertext,
  initialValue,
  checked,
  disabled,
  required,
  containerstyle,
  onChange,
  onFocus,
}: SwitchFieldProps) => {
  const { t_i18n } = useFormatter();
  // Radix reports the new value directly; MUI reported an event whose target.checked had to be
  // read.
  const internalOnChange = useCallback(
    (newChecked: boolean) => {
      setFieldValue(name, newChecked);
      if (typeof onChange === 'function') {
        onChange(name, newChecked ? 'true' : 'false');
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
    <div style={containerstyle}>
      {/* Wrapper kept for the row position; see fds-migration/MIGRATION-DECISIONS.md#switch-formgroup-wrapper */}
      <FormGroup>
        {/* The icon sits next to the switch */}
        <div style={{ width: 'fit-content', display: 'flex', alignItems: 'center', gap: 4 }}>
          <Switch
            name={name}
            // A caller-supplied `checked` wins over the Formik value: three sites drive the control from their own
            // state, and one of them (TriggerEditionOverview) keeps its value outside Formik.
            checked={checked ?? value === true}
            // formik-mui's fieldToSwitch supplied this; without it the 107
            // switches stayed live during submit.
            disabled={disabled ?? isSubmitting}
            required={required}
            label={label}
            onCheckedChange={internalOnChange}
            onFocus={onFocus}
            onBlur={internalOnBlur}
          />
          {tooltip && (
            <Tooltip>
              <TooltipTrigger asChild>
                <InformationOutline fontSize="small" color="primary" style={{ cursor: 'default' }} tabIndex={0} />
              </TooltipTrigger>
              <TooltipContent>{t_i18n(tooltip)}</TooltipContent>
            </Tooltip>
          )}
        </div>
      </FormGroup>
      <FormHelperText>{helpertext}</FormHelperText>
    </div>
  );
};

export default SwitchField;

import React, { FunctionComponent, useState } from 'react';
import { IconButton } from '@mui/material';
import { Visibility, VisibilityOff } from '@mui/icons-material';
import { Field, useField, useFormikContext } from 'formik';
import { useFormatter } from './i18n';
import { fieldSpacingContainerStyle } from '../utils/field';
import TextField from './TextField';

// TODO remove any when component TextField is typescript
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type PasswordTextFieldProps = any & {
  isSecret?: boolean;
  onToggle?: (isVisible: boolean) => void;
};

const PasswordTextField: FunctionComponent<PasswordTextFieldProps> = ({
  onToggle,
  isSecret = false,
  ...textFieldProps
}) => {
  const { t_i18n } = useFormatter();
  const [isVisible, setIsVisible] = useState(false);

  const [field] = useField(textFieldProps);
  const { dirty } = useFormikContext();
  const isUndefinedCredential = isSecret && field.value === undefined;

  const toggleVisibility = () => {
    setIsVisible(!isVisible);
    if (onToggle) onToggle(!isVisible);
  };

  return (
    <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
      <Field
        component={TextField}
        variant="standard"
        type={isVisible ? 'text' : 'password'}
        fullWidth={true}
        style={fieldSpacingContainerStyle}
        {...textFieldProps}
        {...(isSecret && ({
          onSubmit: (name: string, value: string) => {
            if (textFieldProps?.onSubmit && dirty) {
              textFieldProps.onSubmit(name, value);
            }
          },
          placeholder: isUndefinedCredential ? '••••' : undefined,
          InputLabelProps: {
            shrink: isUndefinedCredential ? true : undefined,
          },
        }))}
      />
      {!isUndefinedCredential && (
        <IconButton
          onClick={toggleVisibility}
          aria-label={isVisible ? t_i18n('Hide') : t_i18n('Show')}
          style={{
            position: 'absolute',
            right: 1,
            top: '60%',
            margin: 0,
            padding: 0,
            zIndex: 1,
          }}
          disableRipple
        >
          {isVisible ? <VisibilityOff/> : <Visibility/>}
        </IconButton>
      )}
    </div>
  );
};

export default PasswordTextField;

import React, { FunctionComponent, useState } from 'react';
import { Visibility, VisibilityOff } from '@mui/icons-material';
import { Field, useField, useFormikContext } from 'formik';
import { useFormatter } from './i18n';
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
    <Field
      component={TextField}
      variant="outlined"
      type={isVisible ? 'text' : 'password'}
      fullWidth={true}
      endIcon={isUndefinedCredential ? undefined : {
        type: 'iconButton' as const,
        icon: isVisible ? <VisibilityOff /> : <Visibility />,
        label: isVisible ? t_i18n('Hide') : t_i18n('Show'),
        onClick: toggleVisibility,
      }}
      {...textFieldProps}
      {...(isSecret && ({
        onSubmit: (name: string, value: string) => {
          if (textFieldProps?.onSubmit && dirty) {
            textFieldProps.onSubmit(name, value);
          }
        },
        placeholder: isUndefinedCredential ? '••••' : undefined,
      }))}
    />
  );
};

export default PasswordTextField;

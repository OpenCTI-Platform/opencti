import React, { FunctionComponent, useState } from 'react';
import { IconButton } from '@filigran/design-system';
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
    <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
      <Field
        component={TextField}
        variant="outlined"
        type={isVisible ? 'text' : 'password'}
        fullWidth={true}
        className="mt-5"
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
          variant="default"
          priority="tertiary"
          size="sm"
          onClick={toggleVisibility}
          aria-label={isVisible ? t_i18n('Hide') : t_i18n('Show')}
          style={{ position: 'absolute', right: 1, top: '60%', zIndex: 1 }}
          icon={isVisible ? <VisibilityOff /> : <Visibility />}
        />
      )}
    </div>
  );
};

export default PasswordTextField;

import React, { FunctionComponent, useState } from 'react';
import { IconButton } from '@mui/material';
import { Visibility, VisibilityOff } from '@mui/icons-material';
import { Field } from 'formik';
import { useFormatter } from './i18n';
import { fieldSpacingContainerStyle } from '../utils/field';
import TextField from './TextField';

interface ToggleVisibilityFieldProps {
  label: string;
  name: string;
  onToggle?: (isVisible: boolean) => void;
  onSubmit?: (name: string, value: string | number | null) => void;
}

const ToggleVisibilityField: FunctionComponent<ToggleVisibilityFieldProps> = ({
  name,
  label,
  onToggle,
  onSubmit,
}) => {
  const { t_i18n } = useFormatter();
  const [isVisible, setIsVisible] = useState(false);

  const toggleVisibility = () => {
    setIsVisible(!isVisible);
    if (onToggle) onToggle(!isVisible);
  };

  return (
    <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
      <Field
        component={TextField}
        variant="standard"
        name={name}
        type={isVisible ? 'text' : 'password'}
        label={label}
        fullWidth={true}
        onSubmit={onSubmit}
        style={fieldSpacingContainerStyle}
      />
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
    </div>
  );
};

export default ToggleVisibilityField;

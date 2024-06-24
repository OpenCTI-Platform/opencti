import React, { FunctionComponent } from 'react';
import { Button } from '@mui/material';
import { useFormatter } from './i18n';
import { DrawerControlledDialProps } from '../private/components/common/drawer/Drawer';

interface EditEntityControlledDialProps extends DrawerControlledDialProps {
  color?: 'primary' | 'inherit' | 'secondary' | 'success' | 'error' | 'info' | 'warning';
  size?: 'small' | 'medium' | 'large';
  variant?: 'text' | 'contained' | 'outlined';
  style?: React.CSSProperties;
}

const EditEntityControlledDial: FunctionComponent<EditEntityControlledDialProps> = ({
  onOpen,
  color = 'primary',
  size = 'small',
  variant = 'contained',
  style,
}) => {
  const { t_i18n } = useFormatter();
  const buttonLabel = t_i18n('Update');
  return (
    <Button
      onClick={onOpen}
      color={color}
      variant={variant}
      size={size}
      aria-label={buttonLabel}
      style={style ?? { marginLeft: '3px' }}
    >
      {buttonLabel}
    </Button>
  );
};

export default EditEntityControlledDial;

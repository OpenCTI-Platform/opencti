import React from 'react';
import { Button } from '@mui/material';
import { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { CommonProps } from '@mui/material/OverridableComponent';
import { ButtonOwnProps } from '@mui/material/Button/Button';
import { useFormatter } from './i18n';

const EditEntityControlledDial = ({
  onOpen,
  color = 'primary',
  size = 'small',
  variant = 'outlined',
  style,
}: ButtonOwnProps & CommonProps & DrawerControlledDialProps) => {
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

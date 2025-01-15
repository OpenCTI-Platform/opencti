import React, { FunctionComponent } from 'react';
import { Button } from '@mui/material';
import { DrawerControlledDialProps } from '../private/components/common/drawer/Drawer';
import { useFormatter } from './i18n';

interface UpdateEntityControlledDialProps extends DrawerControlledDialProps {
  color?: 'primary' | 'inherit' | 'secondary' | 'success' | 'error' | 'info' | 'warning';
  size?: 'small' | 'medium' | 'large';
  variant?: 'text' | 'contained' | 'outlined';
  style?: React.CSSProperties;
}

export const UpdateEntityControlledDial: FunctionComponent<UpdateEntityControlledDialProps> = ({
  onOpen,
  color = 'primary',
  size = 'medium',
  variant = 'outlined',
  style,
}) => {
  const { t_i18n } = useFormatter();
  const buttonValue = t_i18n('Update');

  return (
    <Button
      onClick={onOpen}
      color={color}
      size={size}
      variant={variant}
      aria-label={buttonValue}
      title={buttonValue}
      sx={style ?? { float: 'right' }}
    >
      <div style={{ display: 'flex' }}>
        {buttonValue}
      </div>
    </Button>
  );
};

const DefaultUpdateControlledDial = (props: DrawerControlledDialProps) => (
  <UpdateEntityControlledDial {...props} />
);

export default DefaultUpdateControlledDial;

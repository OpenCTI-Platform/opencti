import { Button } from '@mui/material';
import React, { FunctionComponent } from 'react';
import { DrawerControlledDialProps } from '../private/components/common/drawer/Drawer';
import { useFormatter } from './i18n';

interface CreateEntityControlledDialProps extends DrawerControlledDialProps {
  entityType: string;
  color?: 'primary' | 'inherit' | 'secondary' | 'success' | 'error' | 'info' | 'warning';
  size?: 'small' | 'medium' | 'large';
  variant?: 'text' | 'contained' | 'outlined';
  style?: React.CSSProperties;
}

const CreateEntityControlledDial: FunctionComponent<CreateEntityControlledDialProps> = ({
  onOpen,
  entityType,
  color = 'primary',
  size = 'small',
  variant = 'contained',
  style,
}) => {
  const { t_i18n } = useFormatter();
  const buttonValue = `${t_i18n('Create')} ${t_i18n(entityType)}`;
  return (
    <Button
      onClick={onOpen}
      color={color}
      size={size}
      variant={variant}
      aria-label={buttonValue}
      title={buttonValue}
      sx={style ?? {
        marginLeft: '10px',
        padding: '7px 10px',
      }}
    >
      <div style={{ display: 'flex' }}>
        {buttonValue}
      </div>
    </Button>
  );
};

export default CreateEntityControlledDial;

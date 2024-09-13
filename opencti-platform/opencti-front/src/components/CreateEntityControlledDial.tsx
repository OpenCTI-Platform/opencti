import { Button } from '@mui/material';
import React, { FunctionComponent } from 'react';
import { useTheme } from '@mui/styles';
import { Theme } from '@mui/material/styles/createTheme';
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
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const buttonValue = t_i18n('', {
    id: 'Create ...',
    values: { entity_type: t_i18n(`entity_${entityType}`) },
  });
  return (
    <Button
      onClick={onOpen}
      color={color}
      size={size}
      variant={variant}
      aria-label={buttonValue}
      title={buttonValue}
      sx={style ?? { marginLeft: theme.spacing(1) }}
    >
      <div style={{ display: 'flex' }}>
        {buttonValue}
      </div>
    </Button>
  );
};

export default CreateEntityControlledDial;

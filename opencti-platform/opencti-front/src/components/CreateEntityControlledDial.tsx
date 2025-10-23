import { Button } from '@mui/material';
import React, { FunctionComponent } from 'react';
import { useTheme } from '@mui/styles';
import { Theme } from '@mui/material/styles/createTheme';
import { DrawerControlledDialProps } from '../private/components/common/drawer/Drawer';
import { useFormatter } from './i18n';
import useDraftContext from '../utils/hooks/useDraftContext';
import { useGetCurrentUserAccessRight } from '../utils/authorizedMembers';

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
  size = 'medium',
  variant = 'contained',
  style,
}) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const valueString = entityType ? t_i18n(`entity_${entityType}`) : t_i18n('Entity');
  const buttonValue = t_i18n('', {
    id: 'Create ...',
    values: { entity_type: valueString },
  });
  // Remove create button in Draft context without the minimal right access "canEdit"
  const draftContext = useDraftContext();
  const currentAccessRight = useGetCurrentUserAccessRight(draftContext?.currentUserAccessRight);
  const canDisplayButton = !draftContext || currentAccessRight.canEdit;

  return canDisplayButton ? (
    <Button
      onClick={onOpen}
      color={color}
      size={size}
      variant={variant}
      aria-label={buttonValue}
      title={buttonValue}
      data-testid={`create-${entityType.toLowerCase()}-button`}
      sx={style ?? { marginLeft: theme.spacing(1) }}
    >
      {buttonValue}
    </Button>
  ) : (
    <></>
  );
};

export default CreateEntityControlledDial;

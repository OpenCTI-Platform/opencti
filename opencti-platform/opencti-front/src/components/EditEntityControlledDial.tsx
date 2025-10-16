import React from 'react';
import { Button } from '@mui/material';
import { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { CommonProps } from '@mui/material/OverridableComponent';
import { ButtonOwnProps } from '@mui/material/Button/Button';
import { useFormatter } from './i18n';
import useDraftContext from '../utils/hooks/useDraftContext';
import { useGetCurrentUserAccessRight } from '../utils/authorizedMembers';

const EditEntityControlledDial = ({
  onOpen,
  color = 'primary',
  size = 'medium',
  variant = 'contained',
  style,
  disabled = false,
}: ButtonOwnProps & CommonProps & DrawerControlledDialProps) => {
  const { t_i18n } = useFormatter();
  const buttonLabel = t_i18n('Update');
  // Remove create button in Draft context without the minimal right access "canEdit"
  const draftContext = useDraftContext();
  const currentAccessRight = useGetCurrentUserAccessRight(draftContext?.currentUserAccessRight);
  const canDisplayButton = !draftContext || currentAccessRight.canEdit;

  return canDisplayButton && (
    <Button
      onClick={onOpen}
      color={color}
      variant={variant}
      size={size}
      aria-label={buttonLabel}
      style={style ?? { marginLeft: '4px' }}
      disabled={disabled}
    >
      {buttonLabel}
    </Button>
  );
};

export default EditEntityControlledDial;

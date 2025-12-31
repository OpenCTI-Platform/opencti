import React from 'react';
import Button, { CustomButtonProps } from '@common/button/Button';
import { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { CommonProps } from '@mui/material/OverridableComponent';
import { useFormatter } from './i18n';
import useDraftContext from '../utils/hooks/useDraftContext';
import { useGetCurrentUserAccessRight } from '../utils/authorizedMembers';

const EditEntityControlledDial = ({
  onOpen,
  color = 'primary',
  size = 'default',
  variant = 'primary',
  style,
  disabled = false,
}: CustomButtonProps & CommonProps & DrawerControlledDialProps) => {
  const { t_i18n } = useFormatter();
  const buttonLabel = t_i18n('Update');
  // Remove Update button in Draft context without the minimal right access "canEdit"
  const draftContext = useDraftContext();
  const currentAccessRight = useGetCurrentUserAccessRight(draftContext?.currentUserAccessRight);
  const canDisplayButton = !draftContext || currentAccessRight.canEdit;

  return canDisplayButton ? (
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
  ) : (
    <></>
  );
};

export default EditEntityControlledDial;

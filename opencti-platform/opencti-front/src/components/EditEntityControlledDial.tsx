import React from 'react';
import { Button } from '@mui/material';
import { useFormatter } from './i18n';
import { DrawerControlledDialType } from '../private/components/common/drawer/Drawer';

const EditEntityControlledDial: DrawerControlledDialType = ({ onOpen }) => {
  const { t_i18n } = useFormatter();
  const buttonLabel = t_i18n('Update');
  return (
    <Button
      onClick={onOpen}
      variant={'contained'}
      size={'small'}
      aria-label={buttonLabel}
      style={{ marginLeft: '3px' }}
    >
      {buttonLabel}
    </Button>
  );
};

export default EditEntityControlledDial;

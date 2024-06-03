import React from 'react';
import { Button } from '@mui/material';
import { useFormatter } from './i18n';

const EditEntityControlledDial = ({ onOpen }: { onOpen: () => void }) => {
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

import React from 'react';
import { Button } from '@mui/material';
import { Create } from '@mui/icons-material';
import { useFormatter } from 'src/components/i18n';

const EditEntityControlledDial = (isPrimary = false) => {
  const { t_i18n } = useFormatter();
  const controlledDial = ({ onOpen }: {
    onOpen: () => void
  }) => (isPrimary
    ? (
      <Button
        style={{
          marginLeft: '3px',
          fontSize: 'small',
        }}
        variant='contained'
        disableElevation
        onClick={onOpen}
      >
        {t_i18n('Edit')} <Create />
      </Button>
    )
    : (
      <Button
        style={{
          marginLeft: '3px',
          fontSize: 'small',
        }}
        variant='outlined'
        onClick={onOpen}
      >
        {t_i18n('Edit')} <Create />
      </Button>)
  );
  return controlledDial;
};

export default EditEntityControlledDial;

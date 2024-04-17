import React from 'react';
import { Add } from '@mui/icons-material';
import { Button } from '@mui/material';
import { useFormatter } from 'src/components/i18n';

const CreateEntityControlledDial = (entity_type: string) => {
  const { t_i18n } = useFormatter();
  const controlledDial = ({ onOpen }: {
    onOpen: () => void
  }) => (
    <Button
      onClick={onOpen}
      color='primary'
      size='small'
      variant='contained'
      style={{
        marginLeft: '10px',
        padding: '7px 10px',
      }}
    >
      {t_i18n('Create')} {t_i18n(entity_type)} <Add />
    </Button>
  );
  return controlledDial;
};

export default CreateEntityControlledDial;
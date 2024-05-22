import React from 'react';
import { Button } from '@mui/material';
import { useFormatter } from 'src/components/i18n';

const CreateEntityControlledDial = (entity_type: string) => {
  const { t_i18n } = useFormatter();
  const buttonValue = `${t_i18n('Create')} ${t_i18n(entity_type)}`;
  const controlledDial = ({ onOpen }: {
    onOpen: () => void
  }) => (
    <Button
      onClick={onOpen}
      color='primary'
      size='small'
      variant='contained'
      aria-label={buttonValue}
      title={buttonValue}
      sx={{
        marginLeft: '10px',
        padding: '7px 10px',
      }}
    >
      <div style={{ display: 'flex' }}>
        {buttonValue}
      </div>
    </Button>
  );
  return controlledDial;
};

export default CreateEntityControlledDial;

import React from 'react';
import { Add } from '@mui/icons-material';
import { Button } from '@mui/material';
import { useFormatter } from 'src/components/i18n';

const CreateRelationshipControlledDial = ({ onOpen }: {
  onOpen: () => void
}) => {
  const { t_i18n } = useFormatter();
  return (
    <Button
      onClick={onOpen}
      style={{
        marginLeft: '3px',
        fontSize: 'small',
      }}
      variant='contained'
      disableElevation
      data-testid='CreateRelationshipButton'
    >
      {t_i18n('Create Relationship')} <Add />
    </Button>
  );
};

export default CreateRelationshipControlledDial;

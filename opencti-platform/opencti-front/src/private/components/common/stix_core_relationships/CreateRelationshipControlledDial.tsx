import { Button } from '@mui/material';
import React from 'react';
import { useFormatter } from '../../../../components/i18n';

const CreateRelationshipControlledDial = ({ onOpen }: {
  onOpen: () => void
}) => {
  const { t_i18n } = useFormatter();
  return (
    <Button
      onClick={onOpen}
      variant='contained'
      disableElevation
      aria-label={t_i18n('Create Relationship')}
      style={{
        marginLeft: '3px',
        fontSize: 'small',
      }}
    >
      {t_i18n('Create Relationship')}
    </Button>
  );
};

export default CreateRelationshipControlledDial;

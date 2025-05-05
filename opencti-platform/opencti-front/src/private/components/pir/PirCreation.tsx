import React, { useState } from 'react';
import { Dialog } from '@mui/material';
import CreateEntityControlledDial from '../../../components/CreateEntityControlledDial';
import Transition from '../../../components/Transition';
import PirCreationForm from './PirCreationForm';

const PirCreation = () => {
  const [dialogOpen, setDialogOpen] = useState(false);

  return (
    <>
      <CreateEntityControlledDial
        entityType='PIR'
        onOpen={() => setDialogOpen(true)}
      />

      <Dialog
        fullWidth
        open={dialogOpen}
        slots={{ transition: Transition }}
        slotProps={{
          paper: {
            elevation: 1,
            style: { height: '500px' },
          },
        }}
      >
        <PirCreationForm onCancel={() => setDialogOpen(false)} />
      </Dialog>
    </>
  );
};

export default PirCreation;

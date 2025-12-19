import React, { useState } from 'react';
import Paper from '@mui/material/Paper';
import Button from '@common/button/Button';
import Typography from '@mui/material/Typography';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import Dialog from '@mui/material/Dialog';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';

import DialogActions from '@mui/material/DialogActions';
import { useFormatter } from '../../../components/i18n';
import Transition from '../../../components/Transition';

const ProfileLocalStorage: React.FC = () => {
  const { t_i18n } = useFormatter();

  const [displayConfirmation, setDisplayConfirmation] = useState(false);

  return (
    <>
      <Paper
        variant="outlined"
        sx={{
          marginBottom: 3,
          padding: '20px',
          borderRadius: '4px',
        }}
      >
        <Typography
          variant="h1"
          gutterBottom={true}
        >
          {t_i18n('Local settings')}
        </Typography>
        <Alert
          severity="info"
          variant="outlined"
          style={{ margin: '10px 0 0 0' }}
        >
          {t_i18n('Your local storage contains the latest filters and searches used in most views of the platform. Clearing local storage might help to load a page crashing because of some filtering, searching or sorting issue.')}
        </Alert>
        <div style={{ display: 'flex', justifyContent: 'end', marginTop: 16 }}>
          <Button
            onClick={() => setDisplayConfirmation(true)}
          >
            {t_i18n('Clear local storage')}
          </Button>
        </div>
      </Paper>

      {/* Confirmation dialog */}
      <Dialog
        open={displayConfirmation}
        slotProps={{ paper: { elevation: 1 } }}
        keepMounted={false}
        slots={{ transition: Transition }}
        onClose={() => setDisplayConfirmation(false)}
      >
        <DialogTitle>
          {t_i18n('Clear local storage')}
        </DialogTitle>
        <DialogContent>
          <Alert
            icon={false}
            severity="warning"
            variant="outlined"
            sx={{ color: 'text.primary' }}
          >
            <AlertTitle style={{ marginBottom: 0, fontWeight: 400 }}>
              {t_i18n('This will erase all the views settings you have made. All these changes will be lost. Are you sure?')}
            </AlertTitle>
          </Alert>
        </DialogContent>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={() => setDisplayConfirmation(false)}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={() => {
              localStorage.clear();
              setDisplayConfirmation(false);
            }}
          >
            {t_i18n('Validate')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default ProfileLocalStorage;

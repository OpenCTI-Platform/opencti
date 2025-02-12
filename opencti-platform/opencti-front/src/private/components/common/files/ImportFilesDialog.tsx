import React, { FunctionComponent } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogTitle } from '@mui/material';
import Typography from '@mui/material/Typography';
import { useFormatter } from '../../../../components/i18n';
import Transition from '../../../../components/Transition';

interface ImportFilesDialogProps {
  open: boolean;
  handleClose: () => void;
}

const ImportFilesDialog: FunctionComponent<ImportFilesDialogProps> = ({
  open,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();

  return (
    <Dialog
      open={open}
      PaperProps={{ elevation: 1 }}
      TransitionComponent={Transition}
      fullWidth={true}
    >
      <DialogTitle><Typography variant="h5">{t_i18n('Import files')}</Typography> </DialogTitle>
      <DialogContent>

      </DialogContent>
      <DialogActions>
        <Button onClick={() => handleClose()}>
          {t_i18n('Cancel')}
        </Button>
        <Button color="secondary" >{t_i18n('Next')}</Button>
      </DialogActions>
    </Dialog>
  );
};

export default ImportFilesDialog;

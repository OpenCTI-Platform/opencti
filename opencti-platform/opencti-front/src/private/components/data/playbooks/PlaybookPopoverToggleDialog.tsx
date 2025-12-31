import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import React, { UIEvent } from 'react';
import { playbookMutationFieldPatch } from '@components/data/playbooks/PlaybookEditionForm';
import Transition from '../../../../components/Transition';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import stopEvent from '../../../../utils/domEvent';

interface PlaybookPopoverToggleDialogProps {
  playbookRunning: boolean;
  playbookId: string;
  showDialog: boolean;
  close: () => void;
}

const PlaybookPopoverToggleDialog = ({
  playbookRunning,
  playbookId,
  showDialog,
  close,
}: PlaybookPopoverToggleDialogProps) => {
  const { t_i18n } = useFormatter();
  const [commitStart, commiting] = useApiMutation(playbookMutationFieldPatch);

  const submit = (e: UIEvent) => {
    stopEvent(e);
    commitStart({
      variables: {
        id: playbookId,
        input: {
          key: 'playbook_running',
          value: [playbookRunning ? 'false' : 'true'],
        },
      },
      onCompleted: () => close(),
    });
  };

  return (
    <Dialog
      slotProps={{ paper: { elevation: 1 } }}
      open={showDialog}
      keepMounted={true}
      slots={{ transition: Transition }}
      onClose={close}
    >
      <DialogTitle>
        {t_i18n('Are you sure?')}
      </DialogTitle>
      <DialogContent>
        <DialogContentText>
          {!playbookRunning
            ? t_i18n('Do you want to start this playbook?')
            : t_i18n('Do you want to stop this playbook?')
          }
        </DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button variant="secondary" onClick={close} disabled={commiting}>
          {t_i18n('Cancel')}
        </Button>
        <Button onClick={submit} disabled={commiting}>
          {t_i18n('Confirm')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default PlaybookPopoverToggleDialog;

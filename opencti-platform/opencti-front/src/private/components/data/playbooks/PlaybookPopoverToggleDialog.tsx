import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { playbookMutationFieldPatch } from '@components/data/playbooks/PlaybookEditionForm';
import DialogActions from '@mui/material/DialogActions';
import DialogContentText from '@mui/material/DialogContentText';
import { UIEvent } from 'react';
import { useFormatter } from '../../../../components/i18n';
import stopEvent from '../../../../utils/domEvent';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

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
      open={showDialog}
      onClose={close}
      title={t_i18n('Are you sure?')}
    >
      <DialogContentText>
        {!playbookRunning
          ? t_i18n('Do you want to start this playbook?')
          : t_i18n('Do you want to stop this playbook?')
        }
      </DialogContentText>
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

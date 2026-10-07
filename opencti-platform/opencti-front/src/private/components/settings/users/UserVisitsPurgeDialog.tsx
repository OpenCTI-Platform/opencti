import React from 'react';
import { graphql } from 'react-relay';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { MESSAGING$ } from '../../../../relay/environment';
import { hasPayloadErrors } from '../../common/time_machine/timeMachineMutations';
import { UserVisitsPurgeDialogMutation } from './__generated__/UserVisitsPurgeDialogMutation.graphql';

const userVisitsPurgeDialogMutation = graphql`
  mutation UserVisitsPurgeDialogMutation($userId: ID!) {
    userVisitsPurgeForUser(userId: $userId)
  }
`;

interface UserVisitsPurgeDialogProps {
  userId: string;
  isOpen: boolean;
  handleClose: () => void;
}

/**
 * Purge of the last visit markers of a user (used by "New since your last visit").
 * The purge is recorded in the audit log.
 */
const UserVisitsPurgeDialog = ({ userId, isOpen, handleClose }: UserVisitsPurgeDialogProps) => {
  const { t_i18n } = useFormatter();
  const [commitPurge, purging] = useApiMutation<UserVisitsPurgeDialogMutation>(userVisitsPurgeDialogMutation);
  const handlePurge = () => {
    commitPurge({
      variables: { userId },
      onCompleted: (_, errors) => {
        if (hasPayloadErrors(errors)) return;
        MESSAGING$.notifySuccess(t_i18n('The last visit markers of the user have been purged'));
        handleClose();
      },
    });
  };
  return (
    <Dialog open={isOpen} onClose={handleClose} title={t_i18n('Purge the last visit markers')}>
      <Alert icon={false} severity="warning" variant="outlined" sx={{ color: 'text.primary' }}>
        <AlertTitle style={{ marginBottom: 0, fontWeight: 400 }}>
          {t_i18n('Every entity will be considered as never visited by this user. Are you sure?')}
        </AlertTitle>
      </Alert>
      <DialogActions>
        <Button variant="secondary" onClick={handleClose} disabled={purging}>
          {t_i18n('Cancel')}
        </Button>
        <Button
          onClick={handlePurge}
          disabled={purging}
          data-testid="purge-user-last-visits"
        >
          {t_i18n('Validate')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default UserVisitsPurgeDialog;

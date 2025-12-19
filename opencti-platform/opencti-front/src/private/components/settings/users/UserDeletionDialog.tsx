import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { Dialog, DialogActions, DialogContent, DialogTitle } from '@mui/material';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Transition from '../../../../components/Transition';

const userDeletionMutation = graphql`
  mutation UserDeletionDialogDeletionMutation($id: ID!) {
    userEdit(id: $id) {
      delete
    }
  }
`;

interface UserDeletionDialogProps {
  userId: string;
  isOpen: boolean;
  handleClose: () => void;
}

const UserDeletionDialog: FunctionComponent<UserDeletionDialogProps> = ({
  userId,
  isOpen,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [deleting, setDeleting] = useState<boolean>(false);
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('User') },
  });
  const [commit] = useApiMutation(
    userDeletionMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );

  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: { id: userId },
      onCompleted: () => {
        setDeleting(false);
        navigate('/dashboard/settings/accesses/users');
      },
    });
  };

  return (
    <Dialog
      open={isOpen}
      PaperProps={{ elevation: 1 }}
      keepMounted={true}
      TransitionComponent={Transition}
      onClose={handleClose}
    >
      <DialogTitle>{t_i18n('Do you want to delete this user?')}</DialogTitle>
      <DialogContent dividers>
        <ul>
          <li>{t_i18n('All notifications, triggers and digests associated with the user will be deleted.')}</li>
          <li>{t_i18n('All investigations and dashboard where the user is the only admin, will be deleted.')}</li>
        </ul>
        {t_i18n('If you want to keep the associated information, we recommend deactivating the user instead.')}
      </DialogContent>
      <DialogActions>
        <Button
          variant="secondary"
          onClick={handleClose}
          disabled={deleting}
        >
          {t_i18n('Cancel')}
        </Button>
        <Button
          onClick={submitDelete}
          disabled={deleting}
        >
          {t_i18n('Delete')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default UserDeletionDialog;

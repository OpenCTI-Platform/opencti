import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { Button, Dialog, DialogActions, DialogContent, DialogTitle } from '@mui/material';
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
  userId: string,
}

const UserDeletionDialog: FunctionComponent<UserDeletionDialogProps> = ({
  userId,
}) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [deleting, setDeleting] = useState<boolean>(false);
  const [displayDelete, setDisplayDelete] = useState<boolean>(false);
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('User') },
  });
  const [commit] = useApiMutation(
    userDeletionMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );

  const handleOpenDelete = () => setDisplayDelete(true);
  const handleCloseDelete = () => setDisplayDelete(false);
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
    <>
      <Button
        onClick={handleOpenDelete}
        variant='contained'
        color='error'
        disabled={deleting}
        sx={{ marginTop: 2 }}
      >
        {t_i18n('Delete')}
      </Button>
      <Dialog
        open={displayDelete}
        PaperProps={{ elevation: 1 }}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
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
            onClick={handleCloseDelete}
            disabled={deleting}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            color="secondary"
            onClick={submitDelete}
            disabled={deleting}
          >
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default UserDeletionDialog;

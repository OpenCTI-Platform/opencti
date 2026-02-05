import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { DialogActions } from '@mui/material';
import { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

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
      onClose={handleClose}
      title={t_i18n('Do you want to delete this user?')}
    >
      <ul>
        <li>{t_i18n('All notifications, triggers and digests associated with the user will be deleted.')}</li>
        <li>{t_i18n('All investigations and dashboard where the user is the only admin, will be deleted.')}</li>
      </ul>
      {t_i18n('If you want to keep the associated information, we recommend deactivating the user instead.')}
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

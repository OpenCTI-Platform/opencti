import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { DialogActions, DialogContentText } from '@mui/material';
import { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

export const roleDeletionMutation = graphql`
  mutation RoleDeletionDialogMutation($id: ID!) {
    roleEdit(id: $id) {
      delete
    }
  }
`;

interface RoleDeletionDialogProps {
  roleId: string;
  isOpen: boolean;
  handleClose: () => void;
}

const RoleDeletionDialog: FunctionComponent<RoleDeletionDialogProps> = ({
  roleId,
  isOpen,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [deleting, setDeleting] = useState<boolean>(false);

  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('Role') },
  });
  const [commit] = useApiMutation(
    roleDeletionMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );

  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: { id: roleId },
      onCompleted: () => {
        setDeleting(false);
        navigate('/dashboard/settings/accesses/roles');
      },
    });
  };

  return (
    <Dialog
      open={isOpen}
      keepMounted={true}
      onClose={handleClose}
      title={t_i18n('Are you sure?')}
    >
      <DialogContentText>{t_i18n('Do you want to delete this role?')}</DialogContentText>
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

export default RoleDeletionDialog;

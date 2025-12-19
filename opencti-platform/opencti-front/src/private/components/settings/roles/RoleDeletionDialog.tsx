import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { Dialog, DialogActions, DialogTitle } from '@mui/material';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Transition from '../../../../components/Transition';

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
      PaperProps={{ elevation: 1 }}
      keepMounted={true}
      TransitionComponent={Transition}
      onClose={handleClose}
    >
      <DialogTitle>{t_i18n('Do you want to delete this role?')}</DialogTitle>
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

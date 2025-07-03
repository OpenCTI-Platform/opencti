import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { Button, Dialog, DialogActions, DialogContent, DialogContentText } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Transition from '../../../../components/Transition';

const groupDeletionMutation = graphql`
  mutation GroupDeletionDialogContainerDeletionMutation($id: ID!) {
    groupEdit(id: $id) {
      delete
    }
  }
`;

interface GroupDeletionDialogProps {
  groupId: string,
  isOpen: boolean
  handleClose: () => void
}

const GroupDeletionDialog: FunctionComponent<GroupDeletionDialogProps> = ({
  groupId,
  isOpen,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [deleting, setDeleting] = useState<boolean>(false);
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('Group') },
  });
  const [commitDeleteMutation] = useApiMutation(
    groupDeletionMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );

  const submitDelete = () => {
    setDeleting(true);
    commitDeleteMutation({
      variables: { id: groupId },
      onCompleted: () => {
        setDeleting(false);
        navigate('/dashboard/settings/accesses/groups');
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
      <DialogContent>
        <DialogContentText>
          {t_i18n('Do you want to delete this group?')}
        </DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleClose} disabled={deleting}>
          {t_i18n('Cancel')}
        </Button>
        <Button color="secondary" onClick={submitDelete} disabled={deleting}>
          {t_i18n('Delete')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default GroupDeletionDialog;

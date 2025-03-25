import React from 'react';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import { graphql } from 'react-relay';
import { useFormatter } from 'src/components/i18n';
import { deleteNode } from 'src/utils/store';
import useApiMutation from '../../utils/hooks/useApiMutation';

const savedFilterDeleteDialogMutation = graphql`
  mutation SavedFilterDeleteDialogMutation($id: ID!) {
    savedFilterDelete(id: $id)
  }
`;

type SavedFilterDeleteDialogProps = {
  savedFilterToDelete: string;
  onClose: () => void;
};

const SavedFilterDeleteDialog = ({ savedFilterToDelete, onClose }: SavedFilterDeleteDialogProps) => {
  const { t_i18n } = useFormatter();

  const [commit] = useApiMutation(
    savedFilterDeleteDialogMutation,
    undefined,
    {
      successMessage: 'Saved filter deleted with success',
      errorMessage: 'Something went wrong while deleting saved filter',
    },
  );

  const handleSubmitDeleteFilter = () => {
    commit({
      variables: {
        id: savedFilterToDelete,
      },
      updater: (store) => {
        deleteNode(store, 'SavedFilters__savedFilters', {}, savedFilterToDelete);
      },
      onCompleted: () => {
        onClose();
      },
      onError: () => {
        onClose();
      },
    });
  };

  return (
    <Dialog
      open
      PaperProps={{ elevation: 1 }}
      onClose={onClose}
      fullWidth
      maxWidth="xs"
    >
      <DialogTitle>{t_i18n('Confirmation')}</DialogTitle>
      <DialogContent></DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{t_i18n('Cancel')}</Button>
        <Button onClick={handleSubmitDeleteFilter} color="secondary">{t_i18n('Validate')}</Button>
      </DialogActions>
    </Dialog>
  );
};

export default SavedFilterDeleteDialog;

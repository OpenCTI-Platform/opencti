import React from 'react';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import { graphql } from 'react-relay';
import { useFormatter } from 'src/components/i18n';
import { deleteNode } from 'src/utils/store';
import DialogContentText from '@mui/material/DialogContentText';
import getSavedFilterScopeFilter from 'src/components/saved_filters/getSavedFilterScopeFilter';
import useApiMutation from '../../utils/hooks/useApiMutation';

const savedFilterDeleteDialogMutation = graphql`
  mutation SavedFilterDeleteDialogMutation($id: ID!) {
    savedFilterDelete(id: $id)
  }
`;

type SavedFilterDeleteDialogProps = {
  savedFilterToDelete: string;
  onClose: () => void;
  onReset: () => void;
};

const SavedFilterDeleteDialog = ({ savedFilterToDelete, onClose, onReset }: SavedFilterDeleteDialogProps) => {
  const { t_i18n } = useFormatter();

  const [commit] = useApiMutation(
    savedFilterDeleteDialogMutation,
    undefined,
    {
      successMessage: t_i18n('Saved filter successfully removed'),
    },
  );

  const handleSubmitDeleteFilter = () => {
    commit({
      variables: {
        id: savedFilterToDelete,
      },
      updater: (store) => {
        const filters = getSavedFilterScopeFilter(localStorageKey);
        deleteNode(store, 'SavedFilters__savedFilters', { filters }, savedFilterToDelete);
      },
      onCompleted: () => {
        onReset();
        onClose();
      },
      onError: () => {
        onClose();
      },
    });
  };

  return (
    <Dialog
      open={true}
      PaperProps={{ elevation: 1 }}
      onClose={onClose}
      fullWidth
      maxWidth="xs"
    >
      <DialogContent>
        <DialogContentText>
          {t_i18n('Do you want to delete this saved filter ?')}
        </DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{t_i18n('Cancel')}</Button>
        <Button onClick={handleSubmitDeleteFilter} color="secondary">{t_i18n('Validate')}</Button>
      </DialogActions>
    </Dialog>
  );
};

export default SavedFilterDeleteDialog;

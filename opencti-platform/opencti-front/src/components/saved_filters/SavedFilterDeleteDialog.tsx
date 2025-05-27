import React from 'react';
import { graphql } from 'react-relay';
import { useFormatter } from 'src/components/i18n';
import { deleteNode } from 'src/utils/store';
import getSavedFilterScopeFilter from 'src/components/saved_filters/getSavedFilterScopeFilter';
import { useDataTableContext } from 'src/components/dataGrid/components/DataTableContext';
import DeleteDialog from 'src/components/DeleteDialog';
import useDeletion from 'src/utils/hooks/useDeletion';
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
  shouldResetFilters: boolean;
};

const SavedFilterDeleteDialog = ({ savedFilterToDelete, onClose, onReset, shouldResetFilters }: SavedFilterDeleteDialogProps) => {
  const { t_i18n } = useFormatter();

  const {
    useDataTablePaginationLocalStorage: {
      localStorageKey,
    },
  } = useDataTableContext();

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
        deleteNode(store, 'SavedFilters_savedFilters', { filters }, savedFilterToDelete);
      },
      onCompleted: () => {
        if (shouldResetFilters) onReset();
        onClose();
      },
      onError: () => {
        onClose();
      },
    });
  };

  const deletion = useDeletion({});

  return (
    <DeleteDialog
      deletion={deletion}
      isOpen
      message= {t_i18n('Do you want to delete this saved filter?')}
      submitDelete={handleSubmitDeleteFilter}
      onClose={onClose}
    />
  );
};

export default SavedFilterDeleteDialog;

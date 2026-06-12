import React from 'react';
import { graphql } from 'react-relay';
import { useFormatter } from 'src/components/i18n';
import { deleteNode } from 'src/utils/store';
import getSavedFilterScopeFilter from 'src/components/saved_filters/getSavedFilterScopeFilter';
import { useDataTableContext } from 'src/components/dataGrid/components/DataTableContext';
import DeleteDialog from 'src/components/DeleteDialog';
import useDeletion from 'src/utils/hooks/useDeletion';
import { type SavedFiltersSelectionData } from './SavedFilterSelection';
import useApiMutation from '../../utils/hooks/useApiMutation';
import useAuth from '../../utils/hooks/useAuth';
import useHelper from '../../utils/hooks/useHelper';

const savedFilterDeleteDialogMutation = graphql`
  mutation SavedFilterDeleteDialogMutation($id: ID!) {
    savedFilterDelete(id: $id)
  }
`;

type SavedFilterDeleteDialogProps = {
  savedFilterToDelete: SavedFiltersSelectionData;
  onClose: () => void;
  onReset: () => void;
  shouldResetFilters: boolean;
};

const SavedFilterDeleteDialog = ({ savedFilterToDelete, onClose, onReset, shouldResetFilters }: SavedFilterDeleteDialogProps) => {
  const { t_i18n } = useFormatter();
  const { me } = useAuth();

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
        id: savedFilterToDelete.id,
      },
      updater: (store) => {
        const filters = getSavedFilterScopeFilter(localStorageKey);
        deleteNode(store, 'SavedFilters_savedFilters', { filters }, savedFilterToDelete.id);
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

  // Count shared members (exclude the user wanting to delete the filter)
  const sharedMembersCount = (savedFilterToDelete.authorizedMembers ?? [])
    .filter((m) => m.member_id !== me.id).length;

  const message = sharedMembersCount > 0
    ? t_i18n('This saved filter is shared with other members. Are you sure you want to delete it?')
    : t_i18n('Do you want to delete this saved filter?');

  const deletion = useDeletion({});

  return (
    <DeleteDialog
      deletion={deletion}
      isOpen
      message={message}
      submitDelete={handleSubmitDeleteFilter}
      onClose={onClose}
    />
  );
};

export default SavedFilterDeleteDialog;

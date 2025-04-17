import React, { useState } from 'react';
import IconButton from '@mui/material/IconButton';
import { SaveOutlined } from '@mui/icons-material';
import { useFormatter } from 'src/components/i18n';
import Tooltip from '@mui/material/Tooltip';
import SavedFilterCreateDialog from 'src/components/saved_filters/SavedFilterCreateDialog';
import { useDataTableContext } from 'src/components/dataGrid/components/DataTableContext';
import { graphql } from 'react-relay';
import useApiMutation from 'src/utils/hooks/useApiMutation';
import { type SavedFiltersSelectionData } from 'src/components/saved_filters/SavedFilterSelection';

const savedFilterButtonEditMutation = graphql`
  mutation SavedFilterButtonEditMutation($id: ID!, $filters: String!) {
    savedFilterFieldPatch(id: $id, filters: $filters) {
      id
      name
      filters
      scope
    }
  }
`;

type SavedFilterButtonProps = {
  currentSavedFilter: SavedFiltersSelectionData
};

const SavedFilterButton = ({ currentSavedFilter }: SavedFilterButtonProps) => {
  const { t_i18n } = useFormatter();

  const [isSavedDialogOpen, setIsSavedDialogOpen] = useState<boolean>(false);

  const {
    useDataTablePaginationLocalStorage: {
      viewStorage: { filters },
      localStorageKey,
    },
  } = useDataTableContext();

  const [commit] = useApiMutation(
    savedFilterButtonEditMutation,
    undefined,
    { successMessage: 'edit ok' },
  );

  const handleEditSavedFilter = () => {
    commit({
      variables: {
        id: currentSavedFilter.id,
        filters: JSON.stringify(filters),
      },
      updater: (store, item) => {
        console.log('item : ', item);
        console.log('currentSavedFilter : ', currentSavedFilter);
      } });
  };

  const handleOpenDialog = () => setIsSavedDialogOpen(true);
  const handleCloseDialog = () => setIsSavedDialogOpen(false);

  const handleSaveButtonClick = () => {
    if (true) {
      console.log('HERE SAVED EDIT');
      handleEditSavedFilter();
    } else {
      handleOpenDialog();
    }
  };

  const isRestrictedStorageKey = localStorageKey.includes('_stixCoreRelationshipCreationFromEntity');
  if (isRestrictedStorageKey) return null;

  return (
    <>
      <Tooltip title={t_i18n('Save filter')}>
        <span>
          <IconButton
            color="primary"
            onClick={handleSaveButtonClick}
            size="small"
            disabled={!filters?.filters.length && !filters?.filterGroups.length}
            aria-label={t_i18n('Save')}
          >
            <SaveOutlined />
          </IconButton>
        </span>
      </Tooltip>

      {isSavedDialogOpen && (
        <SavedFilterCreateDialog
          isOpen={isSavedDialogOpen}
          onClose={handleCloseDialog}
        />
      )}
    </>
  );
};

export default SavedFilterButton;

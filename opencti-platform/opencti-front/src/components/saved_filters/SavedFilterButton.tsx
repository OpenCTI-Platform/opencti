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
import Badge from '@mui/material/Badge';

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
  currentSavedFilter?: SavedFiltersSelectionData
  setCurrentSavedFilter: (savedFilter: SavedFiltersSelectionData | undefined) => void;
};

const SavedFilterButton = ({ currentSavedFilter, setCurrentSavedFilter }: SavedFilterButtonProps) => {
  const { t_i18n } = useFormatter();

  const [isSavedDialogOpen, setIsSavedDialogOpen] = useState<boolean>(false);

  const {
    useDataTablePaginationLocalStorage: {
      viewStorage: { filters },
      localStorageKey,
    },
  } = useDataTableContext();

  const isEmptyFilters = !filters?.filters.length && !filters?.filterGroups.length;
  const hasSameFilters = currentSavedFilter?.filters === JSON.stringify(filters);

  const [commit] = useApiMutation(
    savedFilterButtonEditMutation,
    undefined,
    { successMessage: 'edit ok' },
  );

  const handleEditSavedFilter = () => {
    if (!currentSavedFilter) return;
    commit({
      variables: {
        id: currentSavedFilter.id,
        filters: JSON.stringify(filters),
      },
      onCompleted: () => {
        setCurrentSavedFilter({
          ...currentSavedFilter,
          filters: JSON.stringify(filters),
        } as SavedFiltersSelectionData);
      },
    });
  };

  const handleOpenDialog = () => setIsSavedDialogOpen(true);
  const handleCloseDialog = () => setIsSavedDialogOpen(false);

  const handleSaveButtonClick = () => {
    if (!hasSameFilters && currentSavedFilter) {
      handleEditSavedFilter();
    } else {
      handleOpenDialog();
    }
  };

  const renderBadge = () => (
    <Badge color="warning" overlap="circular" variant="dot">
      <SaveOutlined />
    </Badge>
  );
  const isDisabled = isEmptyFilters || hasSameFilters;

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
            disabled={isDisabled}
            aria-label={t_i18n('Save')}
          >
            {!hasSameFilters && currentSavedFilter
              ? renderBadge()
              : <SaveOutlined />
            }
          </IconButton>
        </span>
      </Tooltip>

      {isSavedDialogOpen && (
        <SavedFilterCreateDialog
          isOpen={isSavedDialogOpen}
          setCurrentSavedFilter={setCurrentSavedFilter}
          onClose={handleCloseDialog}
        />
      )}
    </>
  );
};

export default SavedFilterButton;

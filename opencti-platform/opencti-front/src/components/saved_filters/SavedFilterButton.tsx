import React, { useState } from 'react';
import IconButton from '@common/button/IconButton';
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
  mutation SavedFilterButtonEditMutation($id: ID!, $input: [EditInput!]!) {
    savedFilterFieldPatch(id: $id, input: $input) {
      id
      name
      filters
      scope
    }
  }
`;

type SavedFilterButtonProps = {
  currentSavedFilter?: SavedFiltersSelectionData;
  setCurrentSavedFilter: (savedFilter: SavedFiltersSelectionData | undefined) => void;
};

const SavedFilterButton = ({ currentSavedFilter, setCurrentSavedFilter }: SavedFilterButtonProps) => {
  const { t_i18n } = useFormatter();

  const [isSavedDialogOpen, setIsSavedDialogOpen] = useState<boolean>(false);

  const {
    useDataTablePaginationLocalStorage: {
      helpers,
      viewStorage: { filters },
      localStorageKey,
    },
  } = useDataTableContext();

  const isEmptyFilters = !filters?.filters.length && !filters?.filterGroups.length;
  const hasSameFilters = currentSavedFilter?.filters === JSON.stringify(filters);

  const [commit] = useApiMutation(
    savedFilterButtonEditMutation,
    undefined,
    { successMessage: 'Saved filter successfully updated' },
  );

  const handleEditSavedFilter = () => {
    if (!currentSavedFilter) return;
    const input = {
      key: 'filters',
      value: [JSON.stringify(filters)],
    };
    commit({
      variables: {
        id: currentSavedFilter.id,
        input,
      },
      onCompleted: () => {
        const newValue = {
          ...currentSavedFilter,
          filters: JSON.stringify(filters),
        };
        setCurrentSavedFilter(newValue);
        helpers.handleChangeSavedFilters(newValue);
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
      <Tooltip title={!isDisabled && currentSavedFilter ? t_i18n('Update filter') : t_i18n('Save filter')}>
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

import React, { SyntheticEvent, useEffect, useState } from 'react';
import SavedFilterDeleteDialog from 'src/components/saved_filters/SavedFilterDeleteDialog';
import { useDataTableContext } from 'src/components/dataGrid/components/DataTableContext';
import { SavedFiltersQuery$data } from 'src/components/saved_filters/__generated__/SavedFiltersQuery.graphql';
import SavedFiltersAutocomplete from 'src/components/saved_filters/SavedFiltersAutocomplete';
import { type AutocompleteInputChangeReason } from '@mui/material/useAutocomplete/useAutocomplete';
import useAuth from '../../utils/hooks/useAuth';

export type SavedFiltersSelectionData = NonNullable<NonNullable<SavedFiltersQuery$data['savedFilters']>['edges']>[0]['node'];

type SavedFilterSelectionProps = {
  isDisabled: boolean;
  data: SavedFiltersSelectionData[];
  currentSavedFilter?: SavedFiltersSelectionData;
  setCurrentSavedFilter: (savedFilter: SavedFiltersSelectionData | undefined) => void;
  onRefetch: () => void;
};

export type SavedFiltersAutocompleteOptionType = {
  label: string;
  value: SavedFiltersSelectionData;
  isOwner: boolean;
  ownerName?: string;
  canManage: boolean;
};

const SavedFilterSelection = ({
  isDisabled,
  data,
  currentSavedFilter,
  setCurrentSavedFilter,
  onRefetch,
}: SavedFilterSelectionProps) => {
  const { me } = useAuth();
  const {
    useDataTablePaginationLocalStorage: {
      localStorageKey,
      helpers,
      viewStorage: { savedFilters },
    },
  } = useDataTableContext();

  const [selectedSavedFilter, setSelectedSavedFilter] = useState<SavedFiltersAutocompleteOptionType>();
  const [inputValue, setInputValue] = useState<string>('');
  const [savedFilterToDelete, setSavedFilterToDelete] = useState<SavedFiltersSelectionData>();

  const options: SavedFiltersAutocompleteOptionType[] = data.map((item) => {
    const isOwner = item.creator_id === me.id;
    const ownerMember = item.authorizedMembers?.find((m) => m.member_id === item.creator_id);
    const ownerName = ownerMember?.name ?? '';

    return {
      label: item.name,
      value: item,
      isOwner,
      ownerName: isOwner ? undefined : ownerName,
      canManage: item.currentUserAccessRight === 'admin',
    };
  });

  // Sort options: "My filters" first, then "Shared with me"; alphabetically within each group
  const sortedOptions = [...options].sort((a, b) => {
    if (a.isOwner && !b.isOwner) return -1;
    if (!a.isOwner && b.isOwner) return 1;
    return a.label.localeCompare(b.label);
  });

  const handleReset = () => {
    setSelectedSavedFilter(undefined);
    setCurrentSavedFilter(undefined);
    setInputValue('');
    helpers.handleRemoveSavedFilters();
  };

  useEffect(() => {
    if (savedFilters) {
      const currentSavedFilters = sortedOptions.find((item) => item.value.id === savedFilters.id);
      if (!currentSavedFilters || !data.length) {
        helpers.handleRemoveSavedFilters();
        return;
      }

      setSelectedSavedFilter(currentSavedFilters);
      setCurrentSavedFilter(currentSavedFilters.value);
      setInputValue(currentSavedFilters.label);
    }
  }, []);

  useEffect(() => {
    if (currentSavedFilter && !selectedSavedFilter) {
      const found = sortedOptions.find((o) => o.value.id === currentSavedFilter.id);
      if (found) {
        setSelectedSavedFilter(found);
        setInputValue(found.label);
      }
    }
    if (!currentSavedFilter && selectedSavedFilter) {
      handleReset();
    }
  }, [currentSavedFilter]);

  // Sync local state when the underlying data changes (e.g. after a name edit)
  useEffect(() => {
    if (selectedSavedFilter) {
      const updated = sortedOptions.find((o) => o.value.id === selectedSavedFilter.value.id);
      if (updated && updated.label !== selectedSavedFilter.label) {
        setSelectedSavedFilter(updated);
        setInputValue(updated.label);
        setCurrentSavedFilter(updated.value);
      }
    }
  }, [data]);

  useEffect(() => {
    if (isDisabled && !!selectedSavedFilter) {
      handleReset();
    }
  }, [isDisabled]);

  const handleChange = (selectionOption: SavedFiltersAutocompleteOptionType) => {
    setSelectedSavedFilter(selectionOption);
    setCurrentSavedFilter(selectionOption.value);
    setInputValue(selectionOption.label);
    helpers.handleChangeSavedFilters(selectionOption.value);
  };

  const onInputChange = (_: SyntheticEvent, value: string, reason: AutocompleteInputChangeReason) => {
    if (reason === 'input') setInputValue(value);
  };

  const resetSavedFilterToDelete = () => setSavedFilterToDelete(undefined);

  const handleDelete = (option: SavedFiltersSelectionData) => setSavedFilterToDelete(option);

  return (
    <>
      <SavedFiltersAutocomplete
        isDisabled={isDisabled}
        options={sortedOptions}
        onDelete={handleDelete}
        onChange={handleChange}
        onInputChange={onInputChange}
        value={selectedSavedFilter}
        inputValue={inputValue}
        localStorageKey={localStorageKey}
        onRefetch={onRefetch}
      />
      {!!savedFilterToDelete && (
        <SavedFilterDeleteDialog
          savedFilterToDelete={savedFilterToDelete}
          onClose={resetSavedFilterToDelete}
          onReset={handleReset}
          shouldResetFilters={savedFilterToDelete.id === selectedSavedFilter?.value.id}
        />
      )}
    </>
  );
};
export default SavedFilterSelection;

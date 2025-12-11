import React, { useState, useEffect, SyntheticEvent } from 'react';
import SavedFilterDeleteDialog from 'src/components/saved_filters/SavedFilterDeleteDialog';
import { useDataTableContext } from 'src/components/dataGrid/components/DataTableContext';
import { SavedFiltersQuery$data } from 'src/components/saved_filters/__generated__/SavedFiltersQuery.graphql';
import SavedFiltersAutocomplete from 'src/components/saved_filters/SavedFiltersAutocomplete';
import { type AutocompleteInputChangeReason } from '@mui/material/useAutocomplete/useAutocomplete';

export type SavedFiltersSelectionData = NonNullable<NonNullable<SavedFiltersQuery$data['savedFilters']>['edges']>[0]['node'];

type SavedFilterSelectionProps = {
  isDisabled: boolean;
  data: SavedFiltersSelectionData[];
  currentSavedFilter?: SavedFiltersSelectionData;
  setCurrentSavedFilter: (savedFilter: SavedFiltersSelectionData | undefined) => void;
};

export type AutocompleteOptionType = {
  label: string;
  value: SavedFiltersSelectionData;
};

const SavedFilterSelection = ({ isDisabled, data, currentSavedFilter, setCurrentSavedFilter }: SavedFilterSelectionProps) => {
  const {
    useDataTablePaginationLocalStorage: {
      helpers,
      viewStorage: { savedFilters },
    },
  } = useDataTableContext();

  const [selectedSavedFilter, setSelectedSavedFilter] = useState<AutocompleteOptionType>();
  const [inputValue, setInputValue] = useState<string>('');
  const [savedFilterToDelete, setSavedFilterToDelete] = useState<string>();

  const options = data.map((item) => ({
    label: item.name,
    value: item,
  }));

  const handleReset = () => {
    setSelectedSavedFilter(undefined);
    setCurrentSavedFilter(undefined);
    setInputValue('');
    helpers.handleRemoveSavedFilters();
  };

  useEffect(() => {
    if (savedFilters) {
      const currentSavedFilters = options.find((item) => item.value.id === savedFilters.id);
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
      setSelectedSavedFilter({
        label: currentSavedFilter.name,
        value: currentSavedFilter,
      });
      setInputValue(currentSavedFilter.name);
    }
    if (!currentSavedFilter && selectedSavedFilter) {
      handleReset();
    }
  }, [currentSavedFilter]);

  useEffect(() => {
    if (isDisabled && !!selectedSavedFilter) {
      handleReset();
    }
  }, [isDisabled]);

  const handleChange = (selectionOption: AutocompleteOptionType) => {
    setSelectedSavedFilter(selectionOption);
    setCurrentSavedFilter(selectionOption.value);
    setInputValue(selectionOption.label);
    helpers.handleChangeSavedFilters(selectionOption.value);
  };

  const onInputChange = (_: SyntheticEvent, value: string, reason: AutocompleteInputChangeReason) => {
    if (reason === 'input') setInputValue(value);
  };

  const resetSavedFilterToDelete = () => setSavedFilterToDelete(undefined);

  const handleDelete = (option: SavedFiltersSelectionData) => setSavedFilterToDelete(option.id);

  return (
    <>
      <SavedFiltersAutocomplete
        isDisabled={isDisabled}
        options={options}
        onDelete={handleDelete}
        onChange={handleChange}
        onInputChange={onInputChange}
        value={selectedSavedFilter}
        inputValue={inputValue}
      />
      {!!savedFilterToDelete && (
        <SavedFilterDeleteDialog
          savedFilterToDelete={savedFilterToDelete}
          onClose={resetSavedFilterToDelete}
          onReset={handleReset}
          shouldResetFilters={savedFilterToDelete === selectedSavedFilter?.value.id}
        />
      )}
    </>
  );
};
export default SavedFilterSelection;

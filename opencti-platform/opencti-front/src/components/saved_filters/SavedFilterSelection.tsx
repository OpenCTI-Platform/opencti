import React, { useState, useEffect, SyntheticEvent } from 'react';
import SavedFilterDeleteDialog from 'src/components/saved_filters/SavedFilterDeleteDialog';
import { useDataTableContext } from 'src/components/dataGrid/components/DataTableContext';
import { SavedFiltersQuery$data } from 'src/components/saved_filters/__generated__/SavedFiltersQuery.graphql';
import SavedFiltersAutocomplete from 'src/components/saved_filters/SavedFiltersAutocomplete';

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
      viewStorage: { filters },
    },
  } = useDataTableContext();

  const [selectedSavedFilter, setSelectedSavedFilter] = useState<AutocompleteOptionType>();
  const [inputValue, setInputValue] = useState<string>('');
  const [savedFilterToDelete, setSavedFilterToDelete] = useState<string>();

  const options = data.map((item) => ({
    label: item.name,
    value: item,
  }));

  useEffect(() => {
    if (currentSavedFilter && !selectedSavedFilter) {
      setSelectedSavedFilter({
        label: currentSavedFilter.name,
        value: currentSavedFilter,
      });
      setInputValue(currentSavedFilter.name);
    }
  }, [currentSavedFilter]);

  const handleResetInput = () => {
    setSelectedSavedFilter(undefined);
    setCurrentSavedFilter(undefined);
    helpers.handleRemoveSavedFilters();
    setInputValue('');
  };

  useEffect(() => {
    if (isDisabled && !!selectedSavedFilter) {
      handleResetInput();
    }
  }, [isDisabled]);

  useEffect(() => {
    if (!filters?.filters.length && !filters?.filterGroups.length) {
      handleResetInput();
    }
  }, [filters]);

  const handleChange = (selectionOption: AutocompleteOptionType) => {
    setSelectedSavedFilter(selectionOption);
    setCurrentSavedFilter(selectionOption.value);
    setInputValue(selectionOption.label);
    helpers.handleChangeSavedFilters(selectionOption.value);
  };

  const onInputChange = (_: SyntheticEvent, value: string) => setInputValue(value);

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
        <SavedFilterDeleteDialog savedFilterToDelete={savedFilterToDelete} onClose={resetSavedFilterToDelete} onReset={handleResetInput} />
      )}
    </>
  );
};
export default SavedFilterSelection;

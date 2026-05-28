import React, { useState, useEffect, SyntheticEvent } from 'react';
import SavedFilterDeleteDialog from 'src/components/saved_filters/SavedFilterDeleteDialog';
import { useDataTableContext } from 'src/components/dataGrid/components/DataTableContext';
import { SavedFiltersQuery$data } from 'src/components/saved_filters/__generated__/SavedFiltersQuery.graphql';
import SavedFiltersAutocomplete from 'src/components/saved_filters/SavedFiltersAutocomplete';
import { type AutocompleteInputChangeReason } from '@mui/material/useAutocomplete/useAutocomplete';
import useAuth from '../../utils/hooks/useAuth';
import { useFormatter } from '../i18n';

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
  group: string;
  ownerName?: string;
  canManage: boolean;
};

const SavedFilterSelection = ({ isDisabled, data, currentSavedFilter, setCurrentSavedFilter }: SavedFilterSelectionProps) => {
  const { me } = useAuth();
  const { t_i18n } = useFormatter();
  const {
    useDataTablePaginationLocalStorage: {
      helpers,
      viewStorage: { savedFilters },
    },
  } = useDataTableContext();

  const [selectedSavedFilter, setSelectedSavedFilter] = useState<AutocompleteOptionType>();
  const [inputValue, setInputValue] = useState<string>('');
  const [savedFilterToDelete, setSavedFilterToDelete] = useState<string>();

  const myFiltersGroupLabel = t_i18n('My filters');

  const options: AutocompleteOptionType[] = data.map((item) => {
    const ownerMember = item.authorizedMembers?.find((m) => m.access_right === 'admin');
    const isOwner = ownerMember?.member_id === me.id;
    const ownerName = ownerMember?.name ?? '';

    return {
      label: item.name,
      value: item,
      group: isOwner ? myFiltersGroupLabel : t_i18n('Shared with me'),
      ownerName: isOwner ? undefined : ownerName,
      canManage: item.currentUserAccessRight === 'admin',
    };
  });

  // Sort options: "My filters" first, then "Shared with me"
  const sortedOptions = [...options].sort((a, b) => {
    if (a.group === myFiltersGroupLabel && b.group !== myFiltersGroupLabel) return -1;
    if (a.group !== myFiltersGroupLabel && b.group === myFiltersGroupLabel) return 1;
    return 0;
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
        options={sortedOptions}
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

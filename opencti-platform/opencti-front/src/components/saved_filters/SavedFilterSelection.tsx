import React, { useState, SyntheticEvent, useEffect } from 'react';
import { Autocomplete } from '@mui/material';
import { SavedFiltersQuery$data } from 'src/components/saved_filters/__generated__/SavedFiltersQuery.graphql';
import TextField from '@mui/material/TextField';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { DeleteOutlined } from '@mui/icons-material';
import { useFormatter } from 'src/components/i18n';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import SavedFilterDeleteDialog from 'src/components/saved_filters/SavedFilterDeleteDialog';
import { useDataTableContext } from 'src/components/dataGrid/components/DataTableContext';

type SavedFiltersSelectionData = SavedFiltersQuery$data['savedFilters']['edges']['node'];

type SavedFilterSelectionProps = {
  isDisabled: boolean;
  data: SavedFiltersSelectionData[];
};

type AutocompleteOptionType = {
  label: string;
  value: SavedFiltersSelectionData;
};

const SavedFilterSelection = ({ isDisabled, data }: SavedFilterSelectionProps) => {
  const { t_i18n } = useFormatter();

  const {
    useDataTablePaginationLocalStorage: {
      helpers,
      viewStorage: { filters },
    },
  } = useDataTableContext();

  const [selectedSavedFilter, setSelectedSavedFilter] = useState<string>('');
  const [savedFilterToDelete, setSavedFilterToDelete] = useState<string>();

  const options = data.map((item) => ({
    label: item.name,
    value: item,
  }));

  const handleResetInput = () => setSelectedSavedFilter('');

  useEffect(() => {
    if (isDisabled && !!selectedSavedFilter) {
      handleResetInput();
    }
  }, [isDisabled]);

  useEffect(() => {
    if (!filters.filters.length && !filters.filterGroups.length) {
      handleResetInput();
    }
  }, [filters]);

  const handleSelect = (selectionOption: SavedFiltersSelectionData) => {
    setSelectedSavedFilter(selectionOption.name);
    helpers.handleSetFilters(JSON.parse(selectionOption.filters));
  };

  const resetSavedFilterToDelete = () => setSavedFilterToDelete(undefined);

  const handleDelete = (option: SavedFiltersSelectionData) => (event: SyntheticEvent) => {
    event.stopPropagation();
    event.preventDefault();
    setSavedFilterToDelete(option.id);
  };

  const renderOption = (params: React.HTMLAttributes<HTMLLIElement> & { key: string }, option: AutocompleteOptionType) => {
    return (
      <Box {...params} key={params.key}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
          <Typography>{option.label}</Typography>
          <Tooltip title={t_i18n('Delete this saved filter')}>
            <IconButton
              color={'primary'}
              onClick={handleDelete(option.value)}
              size="small"
            >
              <DeleteOutlined />
            </IconButton>
          </Tooltip>
        </div>
      </Box>
    );
  };

  return (
    <>
      <Autocomplete
        value={selectedSavedFilter}
        autoHighlight
        disabled={isDisabled}
        options={options}
        sx={{ width: 200 }}
        noOptionsText={t_i18n('No available options')}
        disablePortal
        disableClearable
        onChange={(_, selectedOption) => handleSelect(selectedOption.value)}
        renderOption={renderOption}
        renderInput={(params) => (
          <TextField
            {...params}
            variant="outlined"
            size="small"
            label={t_i18n('Select saved filters')}
          />
        )}
      />
      {!!savedFilterToDelete && (
        <SavedFilterDeleteDialog savedFilterToDelete={savedFilterToDelete} onClose={resetSavedFilterToDelete} onReset={handleResetInput} />
      )}
    </>
  );
};
export default SavedFilterSelection;

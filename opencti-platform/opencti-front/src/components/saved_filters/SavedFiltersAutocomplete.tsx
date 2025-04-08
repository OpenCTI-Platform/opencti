import React, { SyntheticEvent } from 'react';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { DeleteOutlined } from '@mui/icons-material';
import { AutocompleteOptionType, SavedFiltersSelectionData } from 'src/components/saved_filters/SavedFilterSelection';
import { Autocomplete } from '@mui/material';
import TextField from '@mui/material/TextField';
import { useFormatter } from 'src/components/i18n';

type SavedFiltersAutocompleteProps = {
  isDisabled?: boolean;
  value?: AutocompleteOptionType;
  inputValue?: string;
  onSelect?: (selectionOption: AutocompleteOptionType) => void;
  onDelete?: (value: SavedFiltersSelectionData) => void;
  options?: AutocompleteOptionType[];
};
const SavedFiltersAutocomplete = ({ isDisabled, value, inputValue, onSelect, onDelete, options }: SavedFiltersAutocompleteProps) => {
  const { t_i18n } = useFormatter();

  const handleDelete = (option: SavedFiltersSelectionData) => (event: SyntheticEvent) => {
    event.stopPropagation();
    event.preventDefault();
    onDelete?.(option);
  };

  const renderOption = (params: React.HTMLAttributes<HTMLLIElement> & { key: string }, option: AutocompleteOptionType) => {
    return (
      <li {...params} key={params.key}>
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
      </li>
    );
  };

  return (
    <Autocomplete
      value={value}
      disabled={isDisabled}
      inputValue={inputValue}
      options={options ?? []}
      sx={{ width: 200 }}
      noOptionsText={t_i18n('No available options')}
      disablePortal
      disableClearable
      onChange={(_, selectedOption: AutocompleteOptionType) => onSelect?.(selectedOption)}
      renderOption={renderOption}
      renderInput={(params) => (
        <TextField
          {...params}
          variant="outlined"
          size="small"
          label={t_i18n('Select saved filter')}
        />
      )}
    />
  );
};

export default SavedFiltersAutocomplete;

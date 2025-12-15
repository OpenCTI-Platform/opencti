import React, { SyntheticEvent } from 'react';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@common/button/IconButton';
import { DeleteOutlined } from '@mui/icons-material';
import { AutocompleteOptionType, SavedFiltersSelectionData } from 'src/components/saved_filters/SavedFilterSelection';
import { Autocomplete } from '@mui/material';
import TextField from '@mui/material/TextField';
import { useFormatter } from 'src/components/i18n';
import { AutocompleteInputChangeReason } from '@mui/material/useAutocomplete/useAutocomplete';

type SavedFiltersAutocompleteProps = {
  isDisabled?: boolean;
  value?: AutocompleteOptionType;
  inputValue?: string;
  onChange?: (selectionOption: AutocompleteOptionType) => void;
  onInputChange?: (_: SyntheticEvent, value: string, reason: AutocompleteInputChangeReason) => void;
  onDelete?: (value: SavedFiltersSelectionData) => void;
  options?: AutocompleteOptionType[];
};
const SavedFiltersAutocomplete = ({ isDisabled, value, inputValue, onChange, onInputChange, onDelete, options }: SavedFiltersAutocompleteProps) => {
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
              color="primary"
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
      key={value?.value.id}
      disableClearable
      value={value}
      disabled={isDisabled}
      isOptionEqualToValue={(option, v) => option?.value.id === v.value.id}
      inputValue={inputValue}
      options={options ?? []}
      sx={{ width: 200 }}
      noOptionsText={t_i18n('No available options')}
      onChange={(_, selectedOption: AutocompleteOptionType) => onChange?.(selectedOption)}
      onInputChange={onInputChange}
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

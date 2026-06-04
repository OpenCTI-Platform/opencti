import React, { SyntheticEvent, useState } from 'react';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@common/button/IconButton';
import { DeleteOutlined, EditOutlined } from '@mui/icons-material';
import { AutocompleteOptionType, SavedFiltersSelectionData } from 'src/components/saved_filters/SavedFilterSelection';
import { Autocomplete, useTheme } from '@mui/material';
import TextField from '@mui/material/TextField';
import { useFormatter } from 'src/components/i18n';
import { AutocompleteInputChangeReason } from '@mui/material/useAutocomplete/useAutocomplete';
import SavedFilterEditDialog from './SavedFilterEditDialog';
import type { Theme } from '../Theme';

type SavedFiltersAutocompleteProps = {
  isDisabled?: boolean;
  value?: AutocompleteOptionType;
  inputValue?: string;
  onChange?: (selectionOption: AutocompleteOptionType) => void;
  onInputChange?: (_: SyntheticEvent, value: string, reason: AutocompleteInputChangeReason) => void;
  onDelete?: (value: SavedFiltersSelectionData) => void;
  options?: AutocompleteOptionType[];
  localStorageKey?: string;
};
const SavedFiltersAutocomplete = ({
  isDisabled,
  value,
  inputValue,
  onChange,
  onInputChange,
  onDelete,
  options,
  localStorageKey,
}: SavedFiltersAutocompleteProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [savedFilterToEdit, setSavedFilterToEdit] = useState<SavedFiltersSelectionData | undefined>();

  const handleDelete = (option: SavedFiltersSelectionData) => (event: SyntheticEvent) => {
    event.stopPropagation();
    event.preventDefault();
    onDelete?.(option);
  };

  const handleEdit = (option: SavedFiltersSelectionData) => (event: SyntheticEvent) => {
    event.stopPropagation();
    event.preventDefault();
    setSavedFilterToEdit(option);
  };

  const renderOption = (params: React.HTMLAttributes<HTMLLIElement> & { key: string }, option: AutocompleteOptionType) => {
    return (
      <li {...params} key={params.key}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
          <Tooltip title={option.label} enterDelay={500}>
            <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0 }}>
              <Typography component="span">{option.label}</Typography>
              {option.ownerName && (
                <Typography component="span" variant="caption" color="text.secondary" sx={{ ml: 1 }}>
                  ({option.ownerName})
                </Typography>
              )}
            </div>
          </Tooltip>
          {option.canManage && (
            <div style={{ display: 'flex', flexShrink: 0, alignItems: 'center' }}>
              <Tooltip title={t_i18n('Edit this saved filter')}>
                <IconButton
                  color="primary"
                  onClick={handleEdit(option.value)}
                  size="small"
                  sx={{ padding: '4px' }}
                >
                  <EditOutlined sx={{ fontSize: 18 }} />
                </IconButton>
              </Tooltip>
              <Tooltip title={t_i18n('Delete this saved filter')}>
                <IconButton
                  color="primary"
                  onClick={handleDelete(option.value)}
                  size="small"
                  sx={{ padding: '4px' }}
                >
                  <DeleteOutlined sx={{ fontSize: 18 }} />
                </IconButton>
              </Tooltip>
            </div>
          )}
        </div>
      </li>
    );
  };

  return (
    <>
      <Autocomplete
        key={value?.value.id}
        disableClearable
        value={value}
        disabled={isDisabled}
        isOptionEqualToValue={(option, v) => option?.value.id === v.value.id}
        inputValue={inputValue}
        options={options ?? []}
        groupBy={(option) => option.group}
        sx={{ width: 200 }}
        slotProps={{
          listbox: {
            sx: { paddingTop: 0 },
          },
        }}
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
            sx={{
              '& .MuiOutlinedInput-root': {
                backgroundColor: theme.palette.background.secondary,
                '& fieldset': {
                  borderColor: value ? theme.palette.border.secondary : 'transparent!important',
                },
              },
            }}
          />
        )}
      />
      {!!savedFilterToEdit && localStorageKey && (
        <SavedFilterEditDialog
          isOpen={!!savedFilterToEdit}
          onClose={() => setSavedFilterToEdit(undefined)}
          savedFilter={savedFilterToEdit}
          localStorageKey={localStorageKey}
        />
      )}
    </>
  );
};

export default SavedFiltersAutocomplete;

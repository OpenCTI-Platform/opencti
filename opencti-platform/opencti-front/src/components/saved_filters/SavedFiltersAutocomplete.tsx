import React, { SyntheticEvent, useState } from 'react';
import { Combobox, ComboboxContent, ComboboxControls, ComboboxField, ComboboxInput, ComboboxTrigger } from '@filigran/design-system';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@common/button/IconButton';
import { DeleteOutlined, EditOutlined } from '@mui/icons-material';
import { SavedFiltersAutocompleteOptionType, SavedFiltersSelectionData } from 'src/components/saved_filters/SavedFilterSelection';

import { useFormatter } from 'src/components/i18n';

import SavedFilterEditDialog from './SavedFilterEditDialog';

import useGranted from '../../utils/hooks/useGranted';

type SavedFiltersAutocompleteProps = {
  isDisabled?: boolean;
  value?: SavedFiltersAutocompleteOptionType;
  inputValue?: string;
  onChange?: (selectionOption: SavedFiltersAutocompleteOptionType) => void;
  onInputChange?: (value: string) => void;
  onDelete?: (value: SavedFiltersSelectionData) => void;
  options?: SavedFiltersAutocompleteOptionType[];
  localStorageKey?: string;
  onRefetch?: () => void;
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
  onRefetch,
}: SavedFiltersAutocompleteProps) => {
  const hasSharingSavedFiltersCapability = useGranted(['KNOWLEDGE_KNSHAREFILTERS']);

  const { t_i18n } = useFormatter();
  const [savedFilterToEdit, setSavedFilterToEdit] = useState<SavedFiltersSelectionData | undefined>();

  const MY_FILTERS_GROUP_LABEL = t_i18n('My filters');

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

  const renderOption = (option: SavedFiltersAutocompleteOptionType) => {
    const filterLabel = option.ownerName ? `${option.label} (${option.ownerName})` : option.label;
    const filterLabelWithScope = localStorageKey
      ? filterLabel // if localStorageKey, the scope is the same for every saved filters of the list
      : `${filterLabel} - ${t_i18n('Scope')}: ${option.scope}`; // in widgets
    const canManage = option.canManage && (hasSharingSavedFiltersCapability || option.isOwner);
    return (
      <>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
          <Tooltip title={filterLabelWithScope} enterDelay={500}>
            <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0 }}>
              <Typography component="span">{filterLabel}</Typography>
            </div>
          </Tooltip>
          {canManage && localStorageKey && (
            <div style={{ display: 'flex', flexShrink: 0, alignItems: 'center' }}>
              <Tooltip title={t_i18n('Edit this saved filter')}>
                <IconButton
                  color="primary"
                  onClick={handleEdit(option.value)}
                  size="small"
                  sx={{ padding: '4px' }}
                  aria-label={t_i18n('Edit the filter')}
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
                  aria-label={t_i18n('Delete the filter')}
                >
                  <DeleteOutlined sx={{ fontSize: 18 }} />
                </IconButton>
              </Tooltip>
            </div>
          )}
        </div>
      </>
    );
  };

  const handleFiltersGroupBy = (isOwner: boolean) => {
    return isOwner ? MY_FILTERS_GROUP_LABEL : t_i18n('Shared with me');
  };

  return (
    <>
      <Combobox<SavedFiltersAutocompleteOptionType>
        key={value?.value.id}
        labelPosition="none"
        clearable={false}
        value={value ?? null}
        disabled={isDisabled}
        isOptionEqualToValue={(option, v) => option?.value.id === v.value.id}
        isOptionDisabled={(option) => !!option.disabled}
        inputValue={inputValue}
        options={options ?? []}
        groupBy={(option) => handleFiltersGroupBy(option.isOwner)}
        getOptionLabel={(option) => option?.label ?? ''}
        onValueChange={(next) => onChange?.(next as SavedFiltersAutocompleteOptionType)}
        // The callers used to filter on MUI's reason === 'input'; the cause gate
        // is the same test, applied once here instead of in each of them.
        onInputChange={(next, meta) => {
          if (meta.cause === 'type') onInputChange?.(next);
        }}
        renderOption={renderOption}
      >
        <ComboboxField>
          <ComboboxInput aria-label={t_i18n('Select saved filter')} placeholder={t_i18n('Select saved filter')} />
          <ComboboxControls>
            <ComboboxTrigger />
          </ComboboxControls>
        </ComboboxField>
        <ComboboxContent
          emptyMessage={t_i18n('No available options')}
          listAriaLabel={t_i18n('Select saved filter')}
        />
      </Combobox>
      {!!savedFilterToEdit && localStorageKey && (
        <SavedFilterEditDialog
          isOpen={!!savedFilterToEdit}
          onClose={() => setSavedFilterToEdit(undefined)}
          savedFilter={savedFilterToEdit}
          onSaved={onRefetch}
        />
      )}
    </>
  );
};

export default SavedFiltersAutocomplete;

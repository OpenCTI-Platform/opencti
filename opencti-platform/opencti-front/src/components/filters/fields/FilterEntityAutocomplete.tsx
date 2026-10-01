import { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import SearchScopeElement from '@components/common/lists/SearchScopeElement';
// fds:keep-mui gap #155 — Combobox has no multi-select entity-search mode with a search-scope endAdornment yet (see FDS-ORNAMENT note below, fds-migration/LIBRARY-FEEDBACK.md)
import { Autocomplete, AutocompleteChangeReason, AutocompleteInputChangeReason } from '@mui/material';
import { useTheme } from '@mui/material/styles';
// fds:keep-mui gap #155 — paired with the Autocomplete above
import TextField from '@mui/material/TextField';
import { Chip, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { Dispatch, Fragment, FunctionComponent, SetStateAction, SyntheticEvent } from 'react';
import { Filter, FilterEditorInputValue } from '../../../utils/filters/filtersHelpers-types';
import { isStixObjectTypes } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../i18n';
import { useFilterEditorContext } from './FilterEditorContext';
import FilterEntityOption from './FilterEntityOption';
import useFilterEntityOptions from './useFilterEntityOptions';
import { applyValueChange, AUTOCOMPLETE_KEY_ACTIONS, computeValueChange, getEditedValues, isChangeBlocked } from './filterEntityValueActions';

export interface FilterEntityAutocompleteProps {
  filter?: Filter;
  filterKey: string;
  setInputValues: Dispatch<SetStateAction<FilterEditorInputValue[]>>;
  subKey?: string;
  disabled?: boolean;
  label?: string;
}

/**
 * Default value editor of a filter: a multi-select over the entities matching the filter
 * definition, searched server-side through the shared editor state.
 *
 * Split out of FilterValueInput because it is the one value widget that is not a plain
 * controlled input: it owns the entity search, the search-scope adornment and the whole
 * `fds:keep-mui` debt of the filters area (gap #155). FilterValueInput falls back to it for
 * every filter type that has no dedicated widget.
 *
 * The search and the option assembly live in `useFilterEntityOptions`, the value semantics
 * in `filterEntityValueActions`; what remains here is the MUI wiring.
 */
const FilterEntityAutocomplete: FunctionComponent<FilterEntityAutocompleteProps> = ({
  filter,
  filterKey,
  setInputValues,
  subKey,
  disabled = false,
  label,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const { helpers, availableRelationFilterTypes } = useFilterEditorContext();
  const {
    searchKey,
    options,
    selectedOptions,
    inputValue,
    setInputValue,
    triggerSearch,
    searchScope,
    setSearchScope,
  } = useFilterEntityOptions({
    filter,
    filterKey,
    subKey,
    setInputValues,
  });

  const handleAutocompleteChange = (_event: SyntheticEvent, newValue: FilterOptionValue[], reason: AutocompleteChangeReason) => {
    const currentValues = getEditedValues(filter, subKey);
    const change = computeValueChange(currentValues, newValue.map((v) => v.value), reason);
    if (reason === AUTOCOMPLETE_KEY_ACTIONS.SELECT_OPTION) {
      setInputValue('');
    }
    if (change.type === 'none' || isChangeBlocked(change, currentValues, disabled)) return;
    applyValueChange(change, { helpers, filter, subKey });
  };

  return (
    <Autocomplete
      // FDS-ORNAMENT: stays on MUI for this round. Its input endAdornment
      // carries the search-scope selector for STIX object types, which is the
      // gap #155 closes with `adornment` on ComboboxField. FIFTH ornament site.
      // See fds-migration/LIBRARY-FEEDBACK.md
      multiple
      key={searchKey}
      size="small"
      value={selectedOptions}
      inputValue={inputValue}
      getOptionLabel={(option) => option.label ?? ''}
      noOptionsText={t_i18n('No available options')}
      options={options}
      disableClearable={disabled}
      groupBy={(option) => t_i18n(option?.group ? option?.group : label)}
      onInputChange={(event, newInputValue, reason: AutocompleteInputChangeReason) => {
        if (reason === AUTOCOMPLETE_KEY_ACTIONS.INPUT || reason === AUTOCOMPLETE_KEY_ACTIONS.CLEAR) {
          setInputValue(newInputValue);
        }
        if (event && reason === AUTOCOMPLETE_KEY_ACTIONS.INPUT) {
          triggerSearch({ target: { value: newInputValue } } as unknown as SyntheticEvent);
        }
      }}
      onChange={handleAutocompleteChange}
      disableCloseOnSelect
      isOptionEqualToValue={(option, val) => option.value === val.value}
      renderTags={(tagValue, getTagProps) => tagValue.map((option, index) => {
        const { key, onDelete, className } = getTagProps({ index });
        const isLockedValue = disabled && tagValue.length === 1;
        const chip = isLockedValue
          ? (
              <Tooltip key={key}>
                <TooltipTrigger asChild>
                  <span>
                    <Chip className={className} label={option.label} disabled />
                  </span>
                </TooltipTrigger>
                <TooltipContent>
                  {t_i18n('Cannot be removed: the relationship type is required when a filter is configured')}
                </TooltipContent>
              </Tooltip>
            )
          : <Chip key={key} className={className} label={option.label} onDelete={() => onDelete(index)} />;
        // A subKey value list (e.g. regardingOf/dynamicRegardingOf's relationship_type) has no
        // mode of its own in the data model (filterEntityValueActions builds `{ key, values }`
        // with no mode) — toggling it here would silently flip the parent filter's mode instead.
        const showModeToggle = !disabled && !subKey && filter && index < tagValue.length - 1;
        return (
          <Fragment key={key}>
            {chip}
            {showModeToggle && (
              <span
                role="button"
                tabIndex={0}
                onClick={() => helpers?.handleSwitchLocalMode?.(filter)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' || event.key === ' ') helpers?.handleSwitchLocalMode?.(filter);
                }}
                style={{
                  display: 'inline-block',
                  cursor: 'pointer',
                  userSelect: 'none',
                  margin: '0 4px',
                  padding: '2px 6px',
                  borderRadius: 4,
                  fontSize: 12,
                  fontFamily: 'Consolas, monaco, monospace',
                  backgroundColor: theme.palette.action?.disabled,
                }}
              >
                {t_i18n((filter.mode ?? 'or').toUpperCase())}
              </span>
            )}
          </Fragment>
        );
      })}
      renderInput={(paramsInput) => (
        <TextField
          role="search"
          {...paramsInput}
          slotProps={{
            input: {
              ...paramsInput.InputProps,
              type: 'search',
              endAdornment: isStixObjectTypes.includes(searchKey)
                ? (
                    <SearchScopeElement
                      name={searchKey}
                      searchScope={searchScope}
                      setSearchScope={setSearchScope}
                      availableRelationFilterTypes={availableRelationFilterTypes}
                    />
                  )
                : paramsInput.InputProps.endAdornment,
            },
          }}
          label={t_i18n(label)}
          variant="outlined"
          size="small"
          fullWidth={true}
          autoFocus={true}
          onFocus={triggerSearch}
        />
      )}
      renderOption={(props, option) => {
        const currentValues = getEditedValues(filter, subKey);
        const checked = currentValues.includes(option.value);
        const { key, ...otherProps } = props;
        return (
          <FilterEntityOption
            key={key || option.value}
            option={option}
            checked={checked}
            disabled={disabled && checked && currentValues.length === 1}
            liProps={otherProps}
          />
        );
      }}
    />
  );
};

export default FilterEntityAutocomplete;

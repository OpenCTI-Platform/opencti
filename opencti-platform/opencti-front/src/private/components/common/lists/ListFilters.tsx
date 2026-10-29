import React, { useState, SyntheticEvent, ReactNode } from 'react';
import Button from '@common/button/Button';
import { FilterListOutlined, LibraryAddOutlined } from '@mui/icons-material';
import Popover from '@mui/material/Popover';
import Tooltip from '@mui/material/Tooltip';
import { RayEndArrow, RayStartArrow, RelationManyToMany } from 'mdi-material-ui';
import {
  Combobox,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxInput,
  ComboboxTrigger,
  Tooltip as FdsTooltip,
  TooltipContent as FdsTooltipContent,
  TooltipTrigger as FdsTooltipTrigger,
} from '@filigran/design-system';
import { type handleFilterHelpers } from 'src/utils/filters/filtersHelpers-types';
import { type SavedFiltersSelectionData } from 'src/components/saved_filters/SavedFilterSelection';
import { useFormatter } from '../../../../components/i18n';
import {
  useBuildFilterKeysMapFromEntityType,
  getDefaultFilterObject,
  getFilterDefinitionFromFilterKeysMap,
  getFirstDefaultConditionFilter,
} from '../../../../utils/filters/filtersUtils';
import { buildGroupedFilterKeyOptions, isGroupedFilterKeySelection } from '../../../../utils/filters/filterKeyGrouping';
import SavedFilters from '../../../../components/saved_filters/SavedFilters';
import SavedFilterButton from '../../../../components/saved_filters/SavedFilterButton';
import ClearFiltersIcon from 'src/components/filters/ClearFiltersIcon';
import { FILTER_POPOVER_LAYER, fdsLayerClass, filterPopoverPaperSx } from '../../../../utils/fdsLayer';

type ListFiltersProps = {
  handleOpenFilters: (event: SyntheticEvent) => void;
  handleCloseFilters: (event: SyntheticEvent) => void;
  isOpen: boolean;
  anchorEl: Element | null;
  availableFilterKeys: string[];
  filterElement: ReactNode;
  variant?: string;
  type?: string;
  helpers?: handleFilterHelpers;
  required?: boolean;
  entityTypes: string[];
  isDatatable?: boolean;
  disabled?: boolean;
  /** Explains, on hover, why the "Add filter" picker is disabled. Only shown while `disabled`. */
  disabledTooltip?: string;
  hideSavedFilters?: boolean;
  disableAddFilterGroup?: boolean;
  /** Stretches the "Add filter" picker over the free width of its row instead of the fixed 200px. */
  expandAddFilter?: boolean;
};

type ParametersType = {
  icon: ReactNode;
  tooltip: string;
  placeholder: string;
  color: 'primary';
};

type OptionType = {
  value: string;
  label: string;
  groupLabel?: string;
  groupOrder?: number;
  numberOfOccurences?: number;
};

// Synthetic option value, always displayed first in the "Add filter" autocomplete,
// used as the entry point to create a nested filter group.
const ADD_FILTER_GROUP_OPTION_VALUE = '__add_filter_group__';

const ListFilters = ({
  handleOpenFilters,
  handleCloseFilters,
  isOpen,
  anchorEl,
  availableFilterKeys,
  filterElement,
  variant,
  type,
  helpers,
  required = false,
  entityTypes,
  isDatatable = false,
  disabled = false,
  disabledTooltip,
  hideSavedFilters = false,
  disableAddFilterGroup = false,
  expandAddFilter = false,
}: ListFiltersProps) => {
  const { t_i18n } = useFormatter();
  const [currentSavedFilter, setCurrentSavedFilter] = useState<SavedFiltersSelectionData>();

  const filterKeysMap = useBuildFilterKeysMapFromEntityType(entityTypes);
  const [inputValue, setInputValue] = useState('');

  const getParameters = (relationshipType?: string): ParametersType => {
    switch (relationshipType) {
      case 'from': return {
        icon: <RayStartArrow fontSize="medium" />,
        tooltip: t_i18n('Dynamic source filters'),
        placeholder: t_i18n('Dynamic source filters'),
        color: 'primary',
      };
      case 'to': return {
        icon: <RayEndArrow fontSize="medium" />,
        tooltip: t_i18n('Dynamic target filters'),
        placeholder: t_i18n('Dynamic target filters'),
        color: 'primary',
      };
      case 'relationships': return {
        icon: <RelationManyToMany fontSize="medium" />,
        tooltip: t_i18n('Relationship filters'),
        placeholder: t_i18n('Relationship filters'),
        color: 'primary',
      };
      default: return {
        icon: <FilterListOutlined fontSize="medium" />,
        tooltip: t_i18n('Filters'),
        placeholder: t_i18n('Add filter'),
        color: 'primary',
      };
    }
  };

  const { icon, tooltip, placeholder, color } = getParameters(type);

  const handleClearFilters = () => {
    setCurrentSavedFilter(undefined);
    helpers?.handleClearAllFilters();
  };

  const handleChange = (value: string) => {
    const filterDefinition = getFilterDefinitionFromFilterKeysMap(value, filterKeysMap);
    helpers?.handleAddFilterWithEmptyValue(getDefaultFilterObject(value, filterDefinition));
  };

  const isNotUniqEntityTypes = isGroupedFilterKeySelection(entityTypes);

  const options = buildGroupedFilterKeyOptions(availableFilterKeys, entityTypes, filterKeysMap, t_i18n);

  const addFilterGroupOption: OptionType = {
    value: ADD_FILTER_GROUP_OPTION_VALUE,
    label: t_i18n('Add Filter Group'),
    groupLabel: t_i18n('Grouping'),
    groupOrder: Number.MAX_SAFE_INTEGER, // always displayed on top of the other groups
  };

  // Without any filter key (e.g. no entity type chosen yet) a group could only be created empty.
  const isAddFilterGroupDisabled = disableAddFilterGroup || options.length === 0;

  // prepended after the sorts so that it cannot be moved by them
  const allOptions: OptionType[] = isAddFilterGroupDisabled
    ? (options as OptionType[])
    : [addFilterGroupOption, ...(options as OptionType[])];

  const defaultFilterOptions = (unfilteredOptions: OptionType[], inputValue: string) => {
    const search = inputValue.trim().toLowerCase();
    if (!search) return unfilteredOptions;
    return unfilteredOptions.filter((o) => o.label.toLowerCase().includes(search));
  };
  // the synthetic option must never be filtered out by the search input
  const filterOptions = (unfilteredOptions: OptionType[], inputValue: string) => (
    isAddFilterGroupDisabled
      ? defaultFilterOptions(unfilteredOptions.filter((o) => o.value !== ADD_FILTER_GROUP_OPTION_VALUE), inputValue)
      : [
          addFilterGroupOption,
          ...defaultFilterOptions(unfilteredOptions.filter((o) => o.value !== ADD_FILTER_GROUP_OPTION_VALUE), inputValue),
        ]
  );

  const handleAddFilterGroup = () => {
    helpers?.handleAddFilterGroup?.(undefined, getFirstDefaultConditionFilter(options, filterKeysMap));
    setInputValue('');
  };

  return (
    <>
      {variant === 'text' ? (
        <Tooltip title={tooltip}>
          <Button
            onClick={handleOpenFilters}
            startIcon={icon}
            size="small"
          >
            {t_i18n('Filters')}
          </Button>
        </Tooltip>
      ) : (
        <>
          {/* Null value and no <ComboboxLabel>, both deliberate — see fds-migration/MIGRATION-DECISIONS.md#add-filter-picker */}
          {/* The wrapper is layout-neutral (`contents`) unless the tooltip is active, then it takes the picker's size. */}
          <FdsTooltip open={disabled && disabledTooltip ? undefined : false}>
            <FdsTooltipTrigger asChild>
              <div className={disabled && disabledTooltip ? (expandAddFilter ? 'min-w-0 flex-1' : 'w-50 shrink-0') : 'contents'}>
                <Combobox<OptionType>
                  // The Combobox ROOT carries `flex w-full flex-col`, so in a flex row it claims the whole line and
                  // pushes the search field, the funnel and the chips onto lines of their own — the stacked filter bar
                  // reported on the Triggers page and the threat- actor card page.
                  className={expandAddFilter ? 'min-w-0 flex-1' : 'w-50 shrink-0'}
                  options={allOptions}
                  filterOptions={filterOptions}
                  labelPosition="none"
                  value={null}
                  onValueChange={(next) => {
                    const picked = Array.isArray(next) ? next[0] : next;
                    if (picked?.value === ADD_FILTER_GROUP_OPTION_VALUE) {
                      handleAddFilterGroup();
                    } else if (picked?.value) {
                      handleChange(picked.value);
                    }
                    setInputValue('');
                  }}
                  disabled={disabled}
                  required={required}
                  groupBy={isNotUniqEntityTypes ? (option) => option?.groupLabel ?? '' : undefined}
                  getOptionLabel={(option) => option.label}
                  // The row element, its role and its state stay the library's: this only fills the content,
                  // which is how the "Add Filter Group" entry gets its icon back (the MUI renderOption equivalent).
                  renderOption={(option) => (option.value === ADD_FILTER_GROUP_OPTION_VALUE
                    ? (
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                          <LibraryAddOutlined fontSize="small" />
                          {option.label}
                        </span>
                      )
                    : option.label)}
                  inputValue={inputValue}
                  onInputChange={(newValue, meta) => {
                    if (meta.cause !== 'type') {
                      return;
                    }
                    setInputValue(newValue);
                  }}
                >
                  {/* The declared width was shrunk to 119px by the flex row, which cut the label off at 95px of the 101px
                it needs. flexShrink keeps it at 200. */}
                  <ComboboxField style={expandAddFilter ? { width: '100%' } : { width: 200, flexShrink: 0 }}>
                    <ComboboxInput
                      placeholder={placeholder}
                      aria-label={placeholder}
                      required={required}
                    />
                    <ComboboxControls>
                      {/* No aria-label on purpose — see fds-migration/MIGRATION-DECISIONS.md#add-filter-picker */}
                      <ComboboxTrigger />
                    </ComboboxControls>
                  </ComboboxField>
                  <ComboboxContent listAriaLabel={placeholder} />
                </Combobox>
              </div>
            </FdsTooltipTrigger>
            <FdsTooltipContent>{disabledTooltip}</FdsTooltipContent>
          </FdsTooltip>
          {!hideSavedFilters && isDatatable && variant === 'default' && (
            <SavedFilters
              currentSavedFilter={currentSavedFilter}
              setCurrentSavedFilter={setCurrentSavedFilter}
            />
          )}
          {/* The row runs at 8px; the two tertiary icons read as one control and sit closer. */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <ClearFiltersIcon
              disabled={disabled}
              color={color}
              onClear={handleClearFilters}
            />
            {!hideSavedFilters && isDatatable && variant === 'default' && (
              <SavedFilterButton
                currentSavedFilter={currentSavedFilter}
                setCurrentSavedFilter={setCurrentSavedFilter}
              />
            )}
          </div>
        </>
      )}
      <Popover
        slotProps={{
          paper: {
            className: fdsLayerClass(FILTER_POPOVER_LAYER),
            sx: {
              width: 600,
              padding: '20px',
              ...filterPopoverPaperSx,
            },
          },
        }}
        open={isOpen}
        anchorEl={anchorEl}
        onClose={handleCloseFilters}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'center',
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'center',
        }}
        elevation={1}
        className="noDrag"
      >
        {filterElement}
      </Popover>
    </>
  );
};

export default ListFilters;

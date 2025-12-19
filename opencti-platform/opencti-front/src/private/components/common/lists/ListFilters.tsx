import React, { useState, SyntheticEvent, ReactNode } from 'react';
import Button from '@common/button/Button';
import { FilterListOffOutlined, FilterListOutlined } from '@mui/icons-material';
import IconButton from '@common/button/IconButton';
import Popover from '@mui/material/Popover';
import Tooltip from '@mui/material/Tooltip';
import { RayEndArrow, RayStartArrow } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import TextField from '@mui/material/TextField';
import MUIAutocomplete from '@mui/material/Autocomplete';
import { type handleFilterHelpers } from 'src/utils/filters/filtersHelpers-types';
import { type SavedFiltersSelectionData } from 'src/components/saved_filters/SavedFilterSelection';
import { useFormatter } from '../../../../components/i18n';
import { useBuildFilterKeysMapFromEntityType, getDefaultFilterObject, getFilterDefinitionFromFilterKeysMap } from '../../../../utils/filters/filtersUtils';
import SavedFilters from '../../../../components/saved_filters/SavedFilters';
import SavedFilterButton from '../../../../components/saved_filters/SavedFilterButton';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    width: 600,
    padding: 20,
  },
}));

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
};

type ParametersType = {
  icon: ReactNode;
  tooltip: string;
  placeholder: string;
  color: 'primary' | 'success' | 'warning';
};

type OptionType = {
  value: string;
  label: string;
  groupLabel?: string;
  groupOrder?: number;
  numberOfOccurences?: number;
};

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
        color: 'warning',
      };
      case 'to': return {
        icon: <RayEndArrow fontSize="medium" />,
        tooltip: t_i18n('Dynamic target filters'),
        placeholder: t_i18n('Dynamic target filters'),
        color: 'success',
      };
      default: return {
        icon: <FilterListOutlined fontSize="medium" />,
        tooltip: t_i18n('Filters'),
        placeholder: t_i18n('Add filter'),
        color: 'primary',
      };
    }
  };

  const classes = useStyles();

  const { icon, tooltip, placeholder, color } = getParameters(type);

  const handleClearFilters = () => {
    setCurrentSavedFilter(undefined);
    helpers?.handleClearAllFilters();
  };

  const handleChange = (value: string) => {
    const filterDefinition = getFilterDefinitionFromFilterKeysMap(value, filterKeysMap);
    helpers?.handleAddFilterWithEmptyValue(getDefaultFilterObject(value, filterDefinition));
  };

  const isNotUniqEntityTypes = (entityTypes.length === 1 && ['Stix-Core-Object', 'Stix-Domain-Object', 'Stix-Cyber-Observable', 'Container'].includes(entityTypes[0]))
    || (entityTypes.length > 1);

  const options = isNotUniqEntityTypes
    ? availableFilterKeys
        .map((key) => {
          const filterDefinition = getFilterDefinitionFromFilterKeysMap(key, filterKeysMap);
          const subEntityTypes = filterDefinition?.subEntityTypes ?? [];
          const isFilterKeyForAllTypes = (entityTypes.length === 1 && subEntityTypes.some((subType) => entityTypes.includes(subType)))
            || (entityTypes.length > 1 && entityTypes.every((subType) => subEntityTypes.includes(subType)));
          return {
            value: key,
            label: t_i18n(filterDefinition?.label ?? key),
            numberOfOccurences: subEntityTypes.length,

            groupLabel: isFilterKeyForAllTypes
              ? t_i18n('Most used filters')
              : t_i18n('All other filters'),
            groupOrder: isFilterKeyForAllTypes ? 1 : 0,
          };
        })
        .sort((a, b) => a.label.localeCompare(b.label))
        .sort((a, b) => b.groupOrder - a.groupOrder) // 'Most used filters' before 'All other filters'
    : availableFilterKeys
        .map((key) => {
          const filterDefinition = getFilterDefinitionFromFilterKeysMap(key, filterKeysMap);
          return {
            value: key,
            label: t_i18n(filterDefinition?.label ?? key),
          };
        })
        .sort((a, b) => a.label.localeCompare(b.label));

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
          <MUIAutocomplete
            disabled={disabled}
            options={options as OptionType[]}
            groupBy={isNotUniqEntityTypes ? (option) => option?.groupLabel ?? '' : undefined}
            sx={{ width: 200 }}
            value={null}
            onChange={(event, selectOptionValue) => {
              if (selectOptionValue?.value) handleChange(selectOptionValue.value);
            }}
            inputValue={inputValue}
            onInputChange={(event, newValue, reason) => {
              if (reason === 'reset') {
                return;
              }
              setInputValue(newValue);
            }}
            renderInput={(params) => (
              <TextField
                {...params}
                variant="outlined"
                size="small"
                label={placeholder}
                required={required}
              />
            )}
            renderOption={(props, option) => <li {...props}>{option.label}</li>}
          />
          {isDatatable && variant === 'default' && (
            <SavedFilters
              currentSavedFilter={currentSavedFilter}
              setCurrentSavedFilter={setCurrentSavedFilter}
            />
          )}
          <Tooltip title={t_i18n('Clear filters')}>
            <IconButton
              color={color}
              onClick={handleClearFilters}
              size="small"
              disabled={disabled}
            >
              <FilterListOffOutlined fontSize="small" />
            </IconButton>
          </Tooltip>
          {isDatatable && variant === 'default' && (
            <SavedFilterButton
              currentSavedFilter={currentSavedFilter}
              setCurrentSavedFilter={setCurrentSavedFilter}
            />
          )}
        </>
      )}
      <Popover
        classes={{ paper: classes.container }}
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

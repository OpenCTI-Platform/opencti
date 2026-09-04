import React, { useState, SyntheticEvent, ReactNode } from 'react';
import Button from '@common/button/Button';
import { FilterListOutlined } from '@mui/icons-material';
import Popover from '@mui/material/Popover';
import Tooltip from '@mui/material/Tooltip';
import { RayEndArrow, RayStartArrow } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import { Combobox, ComboboxContent, ComboboxControls, ComboboxField, ComboboxInput, ComboboxTrigger } from '@filigran/design-system';
import { type handleFilterHelpers } from 'src/utils/filters/filtersHelpers-types';
import { type SavedFiltersSelectionData } from 'src/components/saved_filters/SavedFilterSelection';
import { useFormatter } from '../../../../components/i18n';
import { useBuildFilterKeysMapFromEntityType, getDefaultFilterObject, getFilterDefinitionFromFilterKeysMap } from '../../../../utils/filters/filtersUtils';
import SavedFilters from '../../../../components/saved_filters/SavedFilters';
import SavedFilterButton from '../../../../components/saved_filters/SavedFilterButton';
import ClearFiltersIcon from 'src/components/filters/ClearFiltersIcon';
import { FILTER_POPOVER_LAYER, fdsLayerClass, filterPopoverPaperSx } from '../../../../utils/fdsLayer';

const WORKFLOW_FILTER_KEYS = ['workflow_user', 'workflow_group', 'workflow_organization'];

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    width: 600,
    padding: 20,
    ...filterPopoverPaperSx,
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
  hideSavedFilters?: boolean;
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
  hideSavedFilters = false,
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

  const isFilterKeyForAllTypes = (subEntityTypes: string[]): boolean => {
    return (entityTypes.length === 1 && subEntityTypes.some((subType) => entityTypes.includes(subType)))
      || (entityTypes.length > 1 && entityTypes.every((subType) => subEntityTypes.includes(subType)));
  };

  const getGroupLabel = (key: string, filterDefinition: ReturnType<typeof getFilterDefinitionFromFilterKeysMap>): string => {
    const subEntityTypes = filterDefinition?.subEntityTypes ?? [];
    const isDraftSpecificKey = subEntityTypes.length > 0 && subEntityTypes.every((t) => t === 'DraftWorkspace');
    if (isDraftSpecificKey) {
      return t_i18n('Draft filters');
    }
    if (WORKFLOW_FILTER_KEYS.includes(key)) {
      return t_i18n('Workflow filters');
    }
    if (isFilterKeyForAllTypes(subEntityTypes)) {
      return t_i18n('Most used filters');
    }
    return t_i18n('All other filters');
  };

  const getGroupOrder = (key: string, filterDefinition: ReturnType<typeof getFilterDefinitionFromFilterKeysMap>): number => {
    const subEntityTypes = filterDefinition?.subEntityTypes ?? [];
    const isDraftSpecificKey = subEntityTypes.length > 0 && subEntityTypes.every((t) => t === 'DraftWorkspace');
    if (WORKFLOW_FILTER_KEYS.includes(key)) {
      return 1;
    }
    if (isDraftSpecificKey) {
      return 2;
    }
    if (isFilterKeyForAllTypes(subEntityTypes)) {
      return 3;
    }
    return 0;
  };

  const options = isNotUniqEntityTypes
    ? availableFilterKeys
        .map((key) => {
          const filterDefinition = getFilterDefinitionFromFilterKeysMap(key, filterKeysMap);
          const subEntityTypes = filterDefinition?.subEntityTypes ?? [];

          return {
            value: key,
            label: t_i18n(filterDefinition?.label ?? key),
            numberOfOccurences: subEntityTypes.length,
            groupLabel: getGroupLabel(key, filterDefinition),
            groupOrder: getGroupOrder(key, filterDefinition),
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
          {/* Null value and no <ComboboxLabel>, both deliberate — see fds-migration/MIGRATION-DECISIONS.md#add-filter-picker */}
          <Combobox<OptionType>
            // The Combobox ROOT carries `flex w-full flex-col`, so in a flex row it claims the whole line and
            // pushes the search field, the funnel and the chips onto lines of their own — the stacked filter bar
            // reported on the Triggers page and the threat- actor card page.
            className="w-50 shrink-0"
            options={options as OptionType[]}
            labelPosition="none"
            value={null}
            onValueChange={(next) => {
              const picked = Array.isArray(next) ? next[0] : next;
              if (picked?.value) handleChange(picked.value);
              setInputValue('');
            }}
            disabled={disabled}
            required={required}
            groupBy={isNotUniqEntityTypes ? (option) => option?.groupLabel ?? '' : undefined}
            getOptionLabel={(option) => option.label}
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
            <ComboboxField style={{ width: 200, flexShrink: 0 }}>
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
        classes={{ paper: `${fdsLayerClass(FILTER_POPOVER_LAYER)} ${classes.container}` }}
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

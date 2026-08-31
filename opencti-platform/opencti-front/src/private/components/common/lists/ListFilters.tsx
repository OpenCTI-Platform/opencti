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
    // Filter popovers: surface on `--bg-elevation-highlight` at layer 1, the
    // fields inside at layer 2. See utils/fdsLayer.ts.
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
          {/* The picker never HOLDS a value: choosing an option adds a filter and
              the field goes straight back to empty, which is why `value` is a
              literal null rather than state. `placeholder` carries the name
              instead of a <ComboboxLabel>: the library renders a label ABOVE the
              control, and this control sits in a flex row beside the unlabelled
              search field — a label here would make this the only tall item in
              the row and re-open the very alignment defect the same pass asks to
              fix. The accessible name is kept on the input. */}
          <Combobox<OptionType>
            // The Combobox ROOT carries `flex w-full flex-col`, so in a flex
            // row it claims the whole line and pushes the search field, the
            // funnel and the chips onto lines of their own — the stacked
            // filter bar reported on the Triggers page and the threat-actor
            // card page. The inner `ComboboxField` was already 200px; the root
            // is what had to be told. `w-50` is 200px, and tailwind-merge drops
            // the `w-full` it replaces.
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
            // ONLY a keystroke may write this field. The picker holds no value,
            // so its text is the user's typing and nothing else. In single mode
            // the library answers a pick with
            // `setInputValue(getOptionLabel(option), "select")` -- it writes the
            // chosen label back into the input -- and accepting that write undid
            // the clear below: the field kept saying "Label" after the filter was
            // added, so filling "Label" a SECOND time changed nothing, fired no
            // input event, never reopened the panel, and the option the page
            // model waits for never appeared (_backgroundTask.spec.ts, second
            // addLabelFilter). `clear` and `reset` are programmatic for the same
            // reason, so the guard is on `type` rather than a list of exclusions.
            onInputChange={(newValue, meta) => {
              if (meta.cause !== 'type') {
                return;
              }
              setInputValue(newValue);
            }}
          >
            {/* The declared width was shrunk to 119px by the flex row, which cut
                the label off at 95px of the 101px it needs. flexShrink keeps it
                at 200. */}
            <ComboboxField style={{ width: 200, flexShrink: 0 }}>
              <ComboboxInput
                placeholder={placeholder}
                aria-label={placeholder}
                required={required}
              />
              <ComboboxControls>
                {/* No aria-label here on purpose. Naming the trigger after the
                    field too gave TWO elements the accessible name "Add filter"
                    -- the input and the chevron -- and getByLabel('Add filter')
                    in filters.pageModel then failed strict mode. The library
                    already names it "Toggle options", which is what every other
                    converted Combobox in this product relies on. */}
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

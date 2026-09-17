import Popover from '@mui/material/Popover';
import { useTheme } from '@mui/material/styles';
import { FunctionComponent, useState } from 'react';
import { Filter, FilterEditorInputValue, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';
import { FilterSearchContext, useFilterDefinition } from '../../utils/filters/filtersUtils';
import type { WidgetHost } from '../../utils/widget/widget';
import { FilterRepresentative } from './FiltersModel';
import QuickRelativeDateFiltersButtons from './QuickRelativeDateFiltersButtons';
import CompositeRegardingOfEditor from './fields/CompositeRegardingOfEditor';
import { FilterEditorProvider, useFilterEditorContext } from './fields/FilterEditorContext';
import FilterOperatorSelect from './fields/FilterOperatorSelect';
import FilterValueInput from './fields/FilterValueInput';
import { FILTER_VALUE_POPOVER_MIN_WIDTH } from './fields/filterFieldLayout';

import { FILTER_POPOVER_LAYER, fdsLayerClass, filterPopoverPaperSx } from '../../utils/fdsLayer';

// The popover edits one existing filter and never offers a key picker, so the tree-wide list of
// selectable filter keys is empty here (it only feeds the nested-group row key select).
const NO_AVAILABLE_FILTER_KEYS: string[] = [];

interface FilterChipMenuProps {
  handleClose: () => void;
  open: boolean;
  params: FilterChipsParameter;
  filters: Filter[];
  helpers?: handleFilterHelpers;
  availableRelationFilterTypes?: Record<string, string[]>;
  filtersRepresentativesMap: Map<string, FilterRepresentative>;
  entityTypes?: string[];
  searchContext?: FilterSearchContext;
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
  host?: WidgetHost;
}

export interface FilterChipsParameter {
  filterId?: string;
  anchorEl?: HTMLElement;
  anchorPosition?: { top: number; left: number };
}

interface FilterChipEditorProps {
  filter?: Filter;
  filterKey: string;
  filterOperator: string;
  handleClose: () => void;
}

/**
 * The editing part of the popover: the operator select and the value editor(s). Rendered keyed
 * by `filter.key` (not `filter.id`) by `FilterChipPopover` below, so that changing the filter's
 * key — which mutates the filter object in place — forces a full unmount/remount of this
 * subtree, resetting stale local state (this component's own `useState` call, and further
 * down `FilterEntityAutocomplete`'s and `FilterDate`'s local state).
 */
const FilterChipEditor: FunctionComponent<FilterChipEditorProps> = ({
  filter,
  filterKey,
  filterOperator,
  handleClose,
}) => {
  const theme = useTheme();
  const { helpers, entityTypes } = useFilterEditorContext();
  const filterDefinition = useFilterDefinition(filterKey, entityTypes);

  const [inputValues, setInputValues] = useState<FilterEditorInputValue[]>(filter ? [filter as FilterEditorInputValue] : []);

  const displayOperatorAndFilter = (fKey: string, subKey?: string, disabled = false) => (
    <>
      <FilterOperatorSelect
        filter={filter}
        filterKey={fKey}
        helpers={helpers}
        setInputValues={setInputValues}
        entityTypes={entityTypes}
        subKey={subKey}
        disabled={disabled}
      />
      <FilterValueInput
        filter={filter}
        filterKey={fKey}
        inputValues={inputValues}
        setInputValues={setInputValues}
        subKey={subKey}
        disabled={disabled}
      />
    </>
  );

  if (filterDefinition?.subFilters && filterDefinition.subFilters.length > 1) {
    return (
      <CompositeRegardingOfEditor
        filter={filter}
        filterKey={filterKey}
        inputValues={inputValues}
        setInputValues={setInputValues}
        showFirstOperator
      />
    );
  }

  return (
    <div style={{ display: 'inline-flex' }}>
      <div
        style={{
          minWidth: FILTER_VALUE_POPOVER_MIN_WIDTH,
          padding: 8,
          display: 'flex',
          flexDirection: 'column',
          gap: 16,
        }}
      >
        {displayOperatorAndFilter(filterKey)}
      </div>
      {filterOperator === 'within'
        && (
          <div style={{ display: 'inline-flex', flexShrink: 0, width: 'max-content' }}>
            <div style={{
              color: theme.palette.text.disabled,
              borderLeft: '0.5px solid',
              marginLeft: '10px',
              marginTop: '10px',
              marginBottom: '10px',
            }}
            />
            <QuickRelativeDateFiltersButtons filter={filter} helpers={helpers} handleClose={handleClose} />
          </div>
        )
      }
    </div>
  );
};

export const FilterChipPopover: FunctionComponent<FilterChipMenuProps> = ({
  params,
  handleClose,
  open,
  filters,
  helpers,
  availableRelationFilterTypes,
  availableEntityTypes,
  availableRelationshipTypes,
  filtersRepresentativesMap,
  entityTypes,
  searchContext,
  host,
}) => {
  const filter = filters.find((f) => f.id === params.filterId);
  const filterKey = filter?.key ?? '';
  const filterOperator = filter?.operator ?? '';

  return (
    <Popover
      open={open}
      anchorReference="anchorPosition"
      anchorPosition={params.anchorPosition ?? { top: 0, left: 0 }}
      onClose={handleClose}
      anchorOrigin={{
        vertical: 'bottom',
        horizontal: 'left',
      }}
      slotProps={{
        paper: {
          elevation: 1,
          className: fdsLayerClass(FILTER_POPOVER_LAYER),
          sx: { ...filterPopoverPaperSx, marginTop: '10px' },
        },
      }}
    >
      <FilterEditorProvider
        helpers={helpers}
        availableFilterKeys={NO_AVAILABLE_FILTER_KEYS}
        entityTypes={entityTypes}
        filtersRepresentativesMap={filtersRepresentativesMap}
        availableEntityTypes={availableEntityTypes}
        availableRelationshipTypes={availableRelationshipTypes}
        availableRelationFilterTypes={availableRelationFilterTypes}
        searchContext={searchContext}
        host={host}
      >
        <FilterChipEditor
          key={filterKey}
          filter={filter}
          filterKey={filterKey}
          filterOperator={filterOperator}
          handleClose={handleClose}
        />
      </FilterEditorProvider>
    </Popover>
  );
};

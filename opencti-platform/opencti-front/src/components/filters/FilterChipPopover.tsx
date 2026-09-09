import Popover from '@mui/material/Popover';
import { useTheme } from '@mui/material/styles';
import { FunctionComponent } from 'react';
import { Filter, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';
import { FilterSearchContext, useFilterDefinition } from '../../utils/filters/filtersUtils';
import type { WidgetHost } from '../../utils/widget/widget';
import { FilterRepresentative } from './FiltersModel';
import QuickRelativeDateFiltersButtons from './QuickRelativeDateFiltersButtons';
import CompositeRegardingOfEditor from './group/CompositeRegardingOfEditor';
import { FilterOperatorAndValue, useFilterEditorState } from './group/FilterRow';

import { FILTER_POPOVER_LAYER, fdsLayerClass, filterPopoverPaperSx } from '../../utils/fdsLayer';

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
  const theme = useTheme();
  const filter = filters.find((f) => f.id === params.filterId);
  const filterKey = filter?.key ?? '';
  const filterOperator = filter?.operator ?? '';
  const filterDefinition = useFilterDefinition(filterKey, entityTypes);

  // The whole editing logic (local state, operator select, value editors) lives in FilterRow,
  // so the popover and the filter group panel can never drift apart.
  const state = useFilterEditorState({
    filter,
    entityTypes,
    availableEntityTypes,
    availableRelationshipTypes,
    availableRelationFilterTypes,
    searchContext,
  });

  const displayOperatorAndFilter = (fKey: string, subKey?: string, disabled = false) => (
    <FilterOperatorAndValue
      filter={filter}
      filterKey={fKey}
      helpers={helpers}
      state={state}
      filtersRepresentativesMap={filtersRepresentativesMap}
      entityTypes={entityTypes}
      availableRelationFilterTypes={availableRelationFilterTypes}
      host={host}
      subKey={subKey}
      disabled={disabled}
    />
  );

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
      {filterDefinition?.subFilters && filterDefinition.subFilters.length > 1
        ? (
            <CompositeRegardingOfEditor
              filter={filter}
              filterKey={filterKey}
              helpers={helpers}
              state={state}
              filtersRepresentativesMap={filtersRepresentativesMap}
              entityTypes={entityTypes}
              availableRelationFilterTypes={availableRelationFilterTypes}
              host={host}
              showFirstOperator
            />
          )
        : (
            <div style={{ display: 'inline-flex' }}>
              <div
                style={{
                  minWidth: 250,
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
          )
      }
    </Popover>
  );
};

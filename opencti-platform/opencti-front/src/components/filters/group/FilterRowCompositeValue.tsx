import Popover from '@mui/material/Popover';
import Box from '@mui/material/Box';
import { useTheme } from '@mui/material/styles';
import { FunctionComponent, useState } from 'react';
import { Filter, handleFilterHelpers } from '../../../utils/filters/filtersHelpers-types';
import { isFilterGroupNotEmpty } from '../../../utils/filters/filtersUtils';
import { FILTER_POPOVER_LAYER, fdsLayerClass, filterPopoverPaperSx } from '../../../utils/fdsLayer';
import type { WidgetHost } from '../../../utils/widget/widget';
import { FilterRepresentative } from '../FiltersModel';
import FilterValuesForDynamicSubKey from '../FilterValuesForDynamicSubKey';
import { FilterEditorState, FilterOperatorAndValue } from './FilterOperatorAndValue';

export interface FilterRowCompositeValueProps {
  filter: Filter;
  helpers?: handleFilterHelpers;
  state: FilterEditorState;
  filtersRepresentativesMap: Map<string, FilterRepresentative>;
  entityTypes?: string[];
  availableRelationFilterTypes?: Record<string, string[]>;
  host?: WidgetHost;
}

/**
 * Read-only value of the 'dynamic' subfilter of a 'dynamicRegardingOf' filter, displayed in the
 * nested-group row (the 'relationship_type' subfilter has its own column next to this one, so it
 * is not shown here). Same 'Dynamic filter' chip + hover tooltip as the root-level filter string
 * (FilterValues / FilterValuesForDynamicSubKey), so the two never drift apart. Clicking it opens a
 * popover with just the nested filter-group editor for that 'dynamic' subfilter.
 */
const FilterRowCompositeValue: FunctionComponent<FilterRowCompositeValueProps> = ({
  filter,
  helpers,
  state,
  filtersRepresentativesMap,
  entityTypes,
  availableRelationFilterTypes,
  host,
}) => {
  const theme = useTheme();
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const dynamicValue = filter.values.find((f) => f.key === 'dynamic')?.values?.[0];
  const hasDynamicValue = isFilterGroupNotEmpty(dynamicValue);

  return (
    <>
      <Box
        data-testid={`filter-row-composite-value-${filter.id}`}
        onClick={(event) => setAnchorEl(event.currentTarget)}
        sx={{
          display: 'flex',
          alignItems: 'center',
          overflow: 'hidden',
          height: '100%',
          padding: '0 8px',
          border: `1px solid ${theme.palette.divider}`,
          borderRadius: 1,
          cursor: 'pointer',
          whiteSpace: 'nowrap',
          '&:hover': {
            borderColor: theme.palette.text.primary,
          },
        }}
      >
        {hasDynamicValue && <FilterValuesForDynamicSubKey filterValue={dynamicValue} />}
      </Box>
      <Popover
        open={!!anchorEl}
        anchorEl={anchorEl}
        onClose={() => setAnchorEl(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
        slotProps={{
          paper: {
            elevation: 1,
            className: fdsLayerClass(FILTER_POPOVER_LAYER),
            sx: { ...filterPopoverPaperSx, marginTop: '10px', minWidth: 250, padding: 1 },
          },
        }}
      >
        <FilterOperatorAndValue
          filter={filter}
          filterKey={filter.key}
          helpers={helpers}
          state={state}
          filtersRepresentativesMap={filtersRepresentativesMap}
          entityTypes={entityTypes}
          availableRelationFilterTypes={availableRelationFilterTypes}
          host={host}
          subKey="dynamic"
          hideOperator
        />
      </Popover>
    </>
  );
};

export default FilterRowCompositeValue;

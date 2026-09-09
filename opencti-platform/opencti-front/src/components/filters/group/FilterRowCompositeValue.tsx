import Popover from '@mui/material/Popover';
import Box from '@mui/material/Box';
import { useTheme } from '@mui/material/styles';
import { FunctionComponent, useState } from 'react';
import { Filter, handleFilterHelpers } from '../../../utils/filters/filtersHelpers-types';
import { useFilterDefinition } from '../../../utils/filters/filtersUtils';
import { FILTER_POPOVER_LAYER, fdsLayerClass, filterPopoverPaperSx } from '../../../utils/fdsLayer';
import type { WidgetHost } from '../../../utils/widget/widget';
import { useFormatter } from '../../i18n';
import { FilterRepresentative } from '../FiltersModel';
import FilterValues from '../FilterValues';
import CompositeRegardingOfEditor from './CompositeRegardingOfEditor';
import { FilterEditorState } from './FilterOperatorAndValue';

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
 * Compact, non-editable-looking summary of a 'regardingOf' / 'dynamicRegardingOf' filter, displayed
 * in place of the usual value editor of a FilterRow (too complex for the 3-column row layout).
 * Clicking it opens a popover with the same composite editor as the root filter chip, so the
 * behaviour and displayed labels never drift apart from the root filter line.
 * Deliberately not a chip: a chip reads as a piece of data, not as an action trigger.
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
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const filterDefinition = useFilterDefinition(filter.key, entityTypes);
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const filterLabel = t_i18n(filterDefinition?.label ?? filter.key);

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
        <FilterValues
          label={filterLabel}
          currentFilter={filter}
          filtersRepresentativesMap={filtersRepresentativesMap}
          entityTypes={entityTypes}
          host={host}
        />
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
            sx: { ...filterPopoverPaperSx, marginTop: '10px' },
          },
        }}
      >
        <CompositeRegardingOfEditor
          filter={filter}
          filterKey={filter.key}
          helpers={helpers}
          state={state}
          filtersRepresentativesMap={filtersRepresentativesMap}
          entityTypes={entityTypes}
          availableRelationFilterTypes={availableRelationFilterTypes}
          host={host}
        />
      </Popover>
    </>
  );
};

export default FilterRowCompositeValue;

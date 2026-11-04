import { Fragment, FunctionComponent } from 'react';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import { FilterRepresentative } from './FiltersModel';
import type { FilterGroup } from '../../utils/filters/filtersHelpers-types';
import { FilterEditorProvider } from './fields/FilterEditorContext';
import FilterGroupPanel from './group/FilterGroupPanel';
import GroupModeChip from './group/GroupModeChip';

// Stable identity, and nothing to pick: this display never edits.
const NO_AVAILABLE_FILTER_KEYS: string[] = [];

interface FilterGroupsVisualDisplayProps {
  filtersRepresentativesMap: Map<string, FilterRepresentative>;
  filterGroups: FilterGroup[];
  filterMode: string;
}

/**
 * Read-only display of whole filter groups: the nested-group editor panel rendered without
 * helpers, i.e. as chips, so it looks like the filters line and the editing panel.
 */
const FilterGroupsVisualDisplay: FunctionComponent<FilterGroupsVisualDisplayProps> = ({
  filtersRepresentativesMap,
  filterGroups,
  filterMode,
}) => (
  <FilterEditorProvider
    availableFilterKeys={NO_AVAILABLE_FILTER_KEYS}
    filtersRepresentativesMap={filtersRepresentativesMap}
  >
    <Stack sx={{ gap: 2 }}>
      {filterGroups.map((group, index) => (
        <Fragment key={group.id ?? `filter-group-${index}`}>
          {index !== 0 && <GroupModeChip mode={filterMode} />}
          <Box sx={{ padding: 2, backgroundColor: 'rgba(0, 0, 0, 0.25)' }}>
            <FilterGroupPanel group={group} />
          </Box>
        </Fragment>
      ))}
    </Stack>
  </FilterEditorProvider>
);

export default FilterGroupsVisualDisplay;

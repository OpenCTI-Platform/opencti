import React, { CSSProperties, FunctionComponent, useState } from 'react';
import { InformationOutline } from 'mdi-material-ui';
import { Chip } from '@filigran/design-system';
import { FilterRepresentative } from './FiltersModel';
import type { FilterGroup } from '../../utils/filters/filtersHelpers-types';
import FilterGroupDialog from './FilterGroupDialog';

interface FilterGroupSummaryButtonProps {
  filterObj: FilterGroup;
  showOnlyFilterGroups?: boolean;
  filtersRepresentativesMap: Map<string, FilterRepresentative>;
  filterStyle?: CSSProperties;
  buttonLabel: string;
  dialogTitle: string;
  dialogDescription?: string;
}

/**
 * Compact stand-in for filters that cannot (or should not) be laid out in place, for instance a
 * read-only line: a single button opening a dialog with the full content of the filters.
 */
const FilterGroupSummaryButton: FunctionComponent<FilterGroupSummaryButtonProps> = ({
  filterObj,
  showOnlyFilterGroups = false,
  filtersRepresentativesMap,
  filterStyle,
  buttonLabel,
  dialogTitle,
  dialogDescription,
}) => {
  const [open, setOpen] = useState(false);

  return (
    <>
      <Chip
        severity="info"
        startIcon={<InformationOutline fontSize="small" />}
        label={buttonLabel}
        onClick={() => setOpen(true)}
        style={filterStyle}
      />
      <FilterGroupDialog
        open={open}
        onClose={() => setOpen(false)}
        filterGroups={showOnlyFilterGroups ? filterObj.filterGroups : [filterObj]}
        filterMode={filterObj.mode}
        jsonObject={filterObj}
        filtersRepresentativesMap={filtersRepresentativesMap}
        title={dialogTitle}
        description={dialogDescription}
        showOnlyFilterGroups={showOnlyFilterGroups}
      />
    </>
  );
};

export default FilterGroupSummaryButton;

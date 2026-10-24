import React, { useEffect, useRef } from 'react';
import Box from '@mui/material/Box';
import Filters from '../../common/lists/Filters';
import FilterIconButton from '../../../../components/FilterIconButton';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import {
  deserializeFilterGroupForFrontend,
  emptyFilterGroup,
  isFilterGroupNotEmpty,
  serializeFilterGroupForBackend,
  useAvailableFilterKeysForEntityTypes,
} from '../../../../utils/filters/filtersUtils';

const SEARCH_CONTEXT = { entityTypes: ['Stix-Core-Object'] };

/**
 * The standard OpenCTI filter builder (every filter key: entity type, malware types, labels, scores...),
 * bound to a filter group serialized in the backend format.
 */
const IrFilterBuilder = ({ value, onChange }: { value: string | null; onChange: (value: string | null) => void }) => {
  const availableFilterKeys = useAvailableFilterKeysForEntityTypes(['Stix-Core-Object']);
  const [filters, helpers] = useFiltersState(deserializeFilterGroupForFrontend(value) ?? emptyFilterGroup);
  const first = useRef(true);
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    onChange(isFilterGroupNotEmpty(filters) ? serializeFilterGroupForBackend(filters) : null);
  }, [filters]);
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <Filters availableFilterKeys={availableFilterKeys} helpers={helpers} searchContext={SEARCH_CONTEXT} />
      </Box>
      <FilterIconButton filters={filters} helpers={helpers} availableFilterKeys={availableFilterKeys} redirection searchContext={SEARCH_CONTEXT} />
    </Box>
  );
};

export default IrFilterBuilder;

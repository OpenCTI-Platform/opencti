import React, { ReactNode } from 'react';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import ProvenanceSourcesCard from './ProvenanceSourcesCard';
import { useIsProvenanceTracked } from '../../../../utils/hooks/useEntitySettings';
import useOverviewLayoutCustomization from '../../../../utils/hooks/useOverviewLayoutCustomization';

export const PROVENANCE_SOURCES_WIDGET_KEY = 'sources';

interface ProvenanceOverviewColumnProps {
  id: string;
  entityType: string;
  // Abstract type carrying the setting of types that have none (relationships, sightings, observables)
  inheritedType?: string;
  children: ReactNode;
}

/**
 * Overview column carrying a card of the element followed by its Sources card, for the types whose provenance is
 * tracked and whose overview layout has no Sources widget. The first card keeps filling the row when the element
 * has no provenance and the Sources card renders nothing.
 */
const ProvenanceOverviewColumn = ({ id, entityType, inheritedType, children }: ProvenanceOverviewColumnProps) => {
  const isTracked = useIsProvenanceTracked(entityType, inheritedType);
  const overviewLayout = useOverviewLayoutCustomization(entityType);
  if (!isTracked || overviewLayout.some(({ key }) => key === PROVENANCE_SOURCES_WIDGET_KEY)) {
    return <>{children}</>;
  }
  return (
    <Stack sx={{ height: '100%', gap: 3 }}>
      <Box sx={{ flex: '1 1 auto', display: 'flex', flexDirection: 'column' }}>
        {children}
      </Box>
      <ProvenanceSourcesCard id={id} />
    </Stack>
  );
};

export default ProvenanceOverviewColumn;

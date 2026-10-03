import React, { ReactNode } from 'react';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import ProvenanceSourcesCard from './ProvenanceSourcesCard';

interface ProvenanceOverviewColumnProps {
  id: string;
  children: ReactNode;
}

/**
 * Overview column carrying a card of the element followed by its Sources card. The first card keeps filling the row
 * when the element has no provenance and the Sources card renders nothing.
 */
const ProvenanceOverviewColumn = ({ id, children }: ProvenanceOverviewColumnProps) => (
  <Stack sx={{ height: '100%', gap: 3 }}>
    <Box sx={{ flex: '1 1 auto', display: 'flex', flexDirection: 'column' }}>
      {children}
    </Box>
    <ProvenanceSourcesCard id={id} />
  </Stack>
);

export default ProvenanceOverviewColumn;

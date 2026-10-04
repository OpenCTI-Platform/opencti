import React, { ReactNode } from 'react';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import ThreatPulseCard from './ThreatPulseCard';

interface ThreatPulseOverviewColumnProps {
  entityId: string;
  children: ReactNode;
}

/**
 * Right column of the overview of a Threat Pulse scoped entity: the overview column (Basic information, then Sources
 * when the element has provenance), then the Threat Pulse card. The overview keeps filling the row when the Threat
 * Pulse card renders nothing.
 */
const ThreatPulseOverviewColumn = ({ entityId, children }: ThreatPulseOverviewColumnProps) => (
  <Stack sx={{ height: '100%', gap: 3 }}>
    <Box sx={{ flex: '1 1 auto', display: 'flex', flexDirection: 'column' }}>
      {children}
    </Box>
    <ThreatPulseCard entityId={entityId} />
  </Stack>
);

export default ThreatPulseOverviewColumn;

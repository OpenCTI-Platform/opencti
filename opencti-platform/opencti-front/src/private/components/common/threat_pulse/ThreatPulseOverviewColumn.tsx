import React, { ReactNode } from 'react';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import ThreatPulseCard from './ThreatPulseCard';

interface ThreatPulseOverviewColumnProps {
  entityId: string;
  children: ReactNode;
}

/**
 * Right column of the overview of a Threat Pulse scoped entity: the Basic information card, which carries the Sources
 * summary, then the Threat Pulse card. The first card keeps filling the row when the second one renders nothing.
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

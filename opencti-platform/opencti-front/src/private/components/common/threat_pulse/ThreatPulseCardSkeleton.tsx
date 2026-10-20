import React from 'react';
import Box from '@mui/material/Box';
import Skeleton from '@mui/material/Skeleton';
import { useFormatter } from '../../../../components/i18n';
import { THREAT_PULSE_FACTS_GRID_SX, THREAT_PULSE_FOOTER_SX } from './ThreatPulseCardSignal';

// The layout of the published signal while the community data loads, so that the card does not jump when it arrives.
// FDS-WORKAROUND #71: the library ships no Skeleton - see fds-migration/LIBRARY-FEEDBACK.md #71.
const ThreatPulseCardSkeleton = () => {
  const { t_i18n } = useFormatter();
  return (
    <Box
      role="status"
      aria-busy="true"
      aria-label={t_i18n('Loading')}
      data-testid="threat-pulse-skeleton"
      sx={{ display: 'flex', flexDirection: 'column', gap: 2.5, flexGrow: 1 }}
    >
      <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
        <Skeleton variant="rounded" width={36} height={36} sx={{ flexShrink: 0 }} />
        <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 1 }}>
          <Skeleton variant="text" width="55%" height={21} />
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Skeleton variant="rounded" width={88} height={24} />
            <Skeleton variant="rounded" width={72} height={24} />
          </Box>
          <Skeleton variant="text" width="65%" height={18} />
        </Box>
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 0.5, flexShrink: 0 }}>
          <Skeleton variant="rounded" width={140} height={32} />
          <Skeleton variant="text" width={64} height={14} />
        </Box>
      </Box>
      <Box sx={THREAT_PULSE_FACTS_GRID_SX}>
        {['first-seen', 'last-seen', 'sector'].map((fact) => (
          <Box key={fact}>
            <Skeleton variant="text" width={96} height={21} />
            <Skeleton variant="text" width={120} height={21} />
          </Box>
        ))}
      </Box>
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Skeleton variant="text" width={130} height={21} />
          <Skeleton variant="rounded" height={6} sx={{ flex: 1 }} />
          <Skeleton variant="text" width={80} height={21} />
        </Box>
        <Skeleton variant="text" width="60%" height={18} />
      </Box>
      <Box sx={THREAT_PULSE_FOOTER_SX}>
        <Skeleton variant="text" width={150} height={18} />
      </Box>
    </Box>
  );
};

export default ThreatPulseCardSkeleton;

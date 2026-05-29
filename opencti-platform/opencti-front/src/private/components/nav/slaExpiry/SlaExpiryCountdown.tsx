import { Box, Typography } from '@mui/material';
import React, { FunctionComponent } from 'react';
import type { SlaExpiryCountdown as SlaExpiryCountdownValue, SlaExpiryPhase } from './slaExpiryTypes';
import { formatSlaExpiryCountdownUnits } from './slaExpiryUtils';

interface SlaExpiryCountdownProps {
  countdown: SlaExpiryCountdownValue;
  phase: SlaExpiryPhase;
  color: string;
  softBackground: string;
}

const CountdownUnit: FunctionComponent<{
  value: string;
  color: string;
  softBackground: string;
  isExpired: boolean;
}> = ({ value, color, softBackground, isExpired }) => (
  <Box
    sx={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      width: 28,
      height: 28,
      borderRadius: '50%',
      backgroundColor: softBackground,
    }}
  >
    <Typography
      component="span"
      sx={{
        fontSize: '0.8125rem',
        fontWeight: 700,
        lineHeight: 1,
        color,
        fontVariantNumeric: isExpired ? undefined : 'tabular-nums',
        letterSpacing: isExpired ? '-0.04em' : undefined,
      }}
    >
      {value}
    </Typography>
  </Box>
);

const SlaExpiryCountdown: FunctionComponent<SlaExpiryCountdownProps> = ({
  countdown,
  phase,
  color,
  softBackground,
}) => {
  const units = formatSlaExpiryCountdownUnits(countdown, phase);
  const isExpired = phase === 'brown';

  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, flexShrink: 0 }}>
      {units.map((unit, index) => (
        <React.Fragment key={index}>
          <CountdownUnit
            value={unit}
            color={color}
            softBackground={softBackground}
            isExpired={isExpired}
          />
          {index < units.length - 1 && (
            <Typography
              component="span"
              sx={{
                fontSize: '0.8125rem',
                fontWeight: 700,
                color,
                lineHeight: 1,
                px: 0.125,
              }}
            >
              :
            </Typography>
          )}
        </React.Fragment>
      ))}
    </Box>
  );
};

export default SlaExpiryCountdown;

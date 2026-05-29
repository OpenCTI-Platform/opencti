import { Box, Typography } from '@mui/material';
import React, { FunctionComponent } from 'react';
import type { SlaExpiryCountdown as SlaExpiryCountdownValue, SlaExpiryPhase } from './slaExpiryTypes';
import {
  formatSlaExpiryCountdownUnits,
  SLA_EXPIRY_EXPIRED_PREFIX,
} from './slaExpiryUtils';

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
}> = ({ value, color, softBackground }) => (
  <Box
    sx={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      width: 28,
      height: 28,
      borderRadius: '50%',
      backgroundColor: softBackground,
      flexShrink: 0,
    }}
  >
    <Typography
      component="span"
      sx={{
        fontSize: '0.8125rem',
        fontWeight: 700,
        lineHeight: 1,
        color,
        fontVariantNumeric: 'tabular-nums',
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
  const isExpired = phase === 'brown';
  const units = formatSlaExpiryCountdownUnits(countdown);

  return (
    <Box
      component="bdi"
      dir="ltr"
      sx={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 0.5,
        flexShrink: 0,
      }}
    >
      <Typography
        component="span"
        aria-hidden={!isExpired}
        sx={{
          fontSize: '0.8125rem',
          fontWeight: 700,
          lineHeight: 1,
          color,
          mr: 0.5,
          visibility: isExpired ? 'visible' : 'hidden',
          flexShrink: 0,
        }}
      >
        {SLA_EXPIRY_EXPIRED_PREFIX}
      </Typography>
      {units.map((unit, index) => (
        <React.Fragment key={index}>
          <CountdownUnit
            value={unit}
            color={color}
            softBackground={softBackground}
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

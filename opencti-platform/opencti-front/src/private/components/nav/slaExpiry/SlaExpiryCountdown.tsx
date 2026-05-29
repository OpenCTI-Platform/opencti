import { Box, Typography } from '@mui/material';
import React, { FunctionComponent } from 'react';
import type { SlaExpiryCountdown as SlaExpiryCountdownValue } from './slaExpiryTypes';
import { padCountdownUnit } from './slaExpiryUtils';

interface SlaExpiryCountdownProps {
  countdown: SlaExpiryCountdownValue;
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
  color,
  softBackground,
}) => {
  const units = [
    padCountdownUnit(countdown.days),
    padCountdownUnit(countdown.hours),
    padCountdownUnit(countdown.minutes),
    padCountdownUnit(countdown.seconds),
  ];

  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, flexShrink: 0 }}>
      {units.map((unit, index) => (
        <React.Fragment key={index}>
          <CountdownUnit value={unit} color={color} softBackground={softBackground} />
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

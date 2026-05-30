import { Box, Collapse, Fade, Stack } from '@mui/material';
import { useTheme } from '@mui/styles';
import React, { FunctionComponent, useEffect, useState } from 'react';
import type { Theme } from '../../../../components/Theme';
import SlaExpiryAlertPill from './SlaExpiryAlertPill';
import { SLA_ALERT_PILL_WIDTH_PX } from './slaExpiryUtils';
import useSlaExpiryAlerts from './useSlaExpiryAlerts';

const EXPAND_TRANSITION_MS = 280;

const STACKED_SHADOW_LAYER = {
  bottom: -3,
  insetX: 16,
} as const;

const SlaExpiryStackedShadow: FunctionComponent<{
  bottom: number;
  insetX: number;
}> = ({ bottom, insetX }) => {
  const theme = useTheme<Theme>();

  return (
    <Box
      aria-hidden
      sx={{
        position: 'absolute',
        left: insetX,
        right: insetX,
        bottom,
        height: '100%',
        borderRadius: 999,
        border: `1px solid ${theme.palette.divider}`,
        backgroundColor: theme.palette.background.paper,
        boxShadow: '0 2px 6px rgba(15, 23, 42, 0.06)',
        zIndex: 0,
        pointerEvents: 'none',
      }}
    />
  );
};

const SlaExpiryAlerts: FunctionComponent = () => {
  const theme = useTheme<Theme>();
  const items = useSlaExpiryAlerts();
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setNowMs(Date.now());
    }, 1000);
    return () => window.clearInterval(timer);
  }, []);

  if (items.length === 0) {
    return null;
  }

  const primaryItem = items[0];
  const additionalItems = items.slice(1);
  const isStacked = items.length > 1;

  const handleToggle = () => {
    if (isStacked) {
      setExpanded((previous) => !previous);
    }
  };

  const renderSingle = () => (
    <SlaExpiryAlertPill item={primaryItem} nowMs={nowMs} />
  );

  const renderStacked = () => (
    <Box
      role="button"
      tabIndex={0}
      onClick={handleToggle}
      onKeyDown={(event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          handleToggle();
        }
      }}
      sx={{
        position: 'relative',
        width: '100%',
        cursor: 'pointer',
        pb: 0.5,
      }}
      aria-expanded={expanded}
      aria-label={`${items.length} SLA alerts`}
    >
      <Fade in={!expanded} timeout={EXPAND_TRANSITION_MS} unmountOnExit>
        <Box
          sx={{
            position: 'absolute',
            inset: 0,
            pointerEvents: 'none',
          }}
        >
          <SlaExpiryStackedShadow
            bottom={STACKED_SHADOW_LAYER.bottom}
            insetX={STACKED_SHADOW_LAYER.insetX}
          />
        </Box>
      </Fade>
      <Box sx={{ position: 'relative', zIndex: 1, width: '100%' }}>
        <SlaExpiryAlertPill item={primaryItem} nowMs={nowMs} />
      </Box>
      <Collapse
        in={expanded}
        timeout={EXPAND_TRANSITION_MS}
        unmountOnExit
        sx={{
          width: '100%',
        }}
      >
        <Stack
          spacing={1}
          sx={{
            pt: 1,
            width: '100%',
          }}
        >
          {additionalItems.map((item) => (
            <SlaExpiryAlertPill key={item.id} item={item} nowMs={nowMs} />
          ))}
        </Stack>
      </Collapse>
    </Box>
  );

  return (
    <Box
      sx={{
        position: 'absolute',
        top: '0',
        left: '50%',
        width: SLA_ALERT_PILL_WIDTH_PX,
        mt: 1,
        zIndex: theme.zIndex.snackbar,
        transform: 'translateX(-50%)',
        pointerEvents: 'none',
        '& > *': {
          pointerEvents: 'auto',
        },
      }}
    >
      {isStacked ? renderStacked() : renderSingle()}
    </Box>
  );
};

export default SlaExpiryAlerts;

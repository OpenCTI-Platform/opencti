import { Box, Stack } from '@mui/material';
import { useTheme } from '@mui/styles';
import React, { FunctionComponent, useEffect, useMemo, useState } from 'react';
import type { Theme } from '../../../../components/Theme';
import SlaExpiryAlertPill from './SlaExpiryAlertPill';
import { compareSlaExpiryUrgency } from './slaExpiryUtils';
import useSlaExpiryAlerts from './useSlaExpiryAlerts';

/** Matches SlaExpiryAlertPill minWidth so centering does not shift on toggle. */
const SLA_ALERT_PILL_WIDTH_PX = 380;

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

  const sortedItems = useMemo(
    () => [...items].sort((a, b) => compareSlaExpiryUrgency(a, b, nowMs)),
    [items, nowMs],
  );

  if (sortedItems.length === 0) {
    return null;
  }

  const primaryItem = sortedItems[0];
  const isStacked = sortedItems.length > 1;

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
        // Reserve space for the stacked shadow layer in both collapsed and expanded states.
        pb: 0.5,
      }}
      aria-expanded={expanded}
      aria-label={`${sortedItems.length} SLA alerts`}
    >
      {!expanded && (
        <SlaExpiryStackedShadow
          bottom={STACKED_SHADOW_LAYER.bottom}
          insetX={STACKED_SHADOW_LAYER.insetX}
        />
      )}
      {expanded ? (
        <Stack
          spacing={1}
          sx={{
            position: 'relative',
            zIndex: 1,
            width: '100%',
            maxHeight: 'min(50vh, 360px)',
            overflowY: 'auto',
          }}
        >
          {sortedItems.map((item) => (
            <SlaExpiryAlertPill key={item.id} item={item} nowMs={nowMs} />
          ))}
        </Stack>
      ) : (
        <Box sx={{ position: 'relative', zIndex: 1, width: '100%' }}>
          <SlaExpiryAlertPill item={primaryItem} nowMs={nowMs} />
        </Box>
      )}
    </Box>
  );

  return (
    <Box
      sx={{
        position: 'absolute',
        top: '100%',
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

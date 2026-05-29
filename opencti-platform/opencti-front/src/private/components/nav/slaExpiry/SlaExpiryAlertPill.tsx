import { ReportProblem } from '@mui/icons-material';
import { Box, Typography } from '@mui/material';
import { useTheme } from '@mui/styles';
import React, { FunctionComponent } from 'react';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import type { SlaExpiryAlertItem } from './slaExpiryTypes';
import SlaExpiryCountdown from './SlaExpiryCountdown';
import {
  getSlaExpiryCountdown,
  getSlaExpiryOverdueElapsed,
  getSlaExpiryPhaseStyle,
  getSlaExpiryTitleMessageKey,
} from './slaExpiryUtils';

interface SlaExpiryAlertPillProps {
  item: SlaExpiryAlertItem;
  nowMs: number;
}

/** Matches ReportProblem icon size for symmetric edge spacing. */
const SLA_ALERT_ICON_SIZE_PX = 22;

const SlaExpiryAlertPill: FunctionComponent<SlaExpiryAlertPillProps> = ({
  item,
  nowMs,
}) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const phaseStyle = getSlaExpiryPhaseStyle(item, nowMs);
  const countdown = phaseStyle.phase === 'brown'
    ? getSlaExpiryOverdueElapsed(item.endTime, nowMs)
    : getSlaExpiryCountdown(item.endTime, nowMs);
  const title = t_i18n(getSlaExpiryTitleMessageKey(phaseStyle.phase));

  return (
    <Box
      sx={{
        position: 'relative',
        display: 'flex',
        alignItems: 'center',
        gap: 1.25,
        px: 1.5,
        py: 1,
        width: '100%',
        boxSizing: 'border-box',
        borderRadius: 999,
        border: `1px solid ${phaseStyle.main}`,
        backgroundColor: theme.palette.background.paper,
        boxShadow: '0 4px 14px rgba(15, 23, 42, 0.08)',
      }}
    >
      <ReportProblem
        sx={{
          fontSize: SLA_ALERT_ICON_SIZE_PX,
          color: phaseStyle.main,
          flexShrink: 0,
        }}
      />
      <Box sx={{ flex: 1, minWidth: 0 }}>
        <Typography
          component="div"
          sx={{
            fontSize: '0.625rem',
            fontWeight: 600,
            letterSpacing: '0.06em',
            lineHeight: 1.2,
            color: theme.palette.text.secondary,
            textTransform: 'uppercase',
          }}
        >
          {item.categoryLabel}
        </Typography>
        <Typography
          component="div"
          sx={{
            fontSize: '0.9375rem',
            fontWeight: 700,
            lineHeight: 1.25,
            color: theme.palette.text.primary,
            whiteSpace: 'nowrap',
          }}
        >
          {title}
        </Typography>
      </Box>
      <SlaExpiryCountdown
        countdown={countdown}
        phase={phaseStyle.phase}
        color={phaseStyle.main}
        softBackground={phaseStyle.soft}
      />
      <Box
        aria-hidden
        sx={{
          width: SLA_ALERT_ICON_SIZE_PX,
          height: SLA_ALERT_ICON_SIZE_PX,
          flexShrink: 0,
        }}
      />
    </Box>
  );
};

export default SlaExpiryAlertPill;

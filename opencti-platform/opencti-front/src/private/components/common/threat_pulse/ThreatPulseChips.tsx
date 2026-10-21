import React from 'react';
import TrendingDown from '@mui/icons-material/TrendingDown';
import TrendingFlat from '@mui/icons-material/TrendingFlat';
import TrendingUp from '@mui/icons-material/TrendingUp';
import { Chip } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import { PULSE_PREVALENCE_LABELS, PULSE_PREVALENCE_SEVERITIES, PULSE_TREND_LABELS, PULSE_TREND_SEVERITIES } from './threatPulseUtils';

const TREND_ICONS: Record<string, typeof TrendingUp> = {
  rising: TrendingUp,
  stable: TrendingFlat,
  falling: TrendingDown,
};

// A community or sector trend: its direction drawn as well as named, so that colour never carries it alone.
export const ThreatPulseTrendChip = ({ trend, testId }: { trend: string; testId?: string }) => {
  const { t_i18n } = useFormatter();
  const TrendIcon = TREND_ICONS[trend];
  return (
    <Chip
      label={t_i18n(PULSE_TREND_LABELS[trend] ?? trend)}
      severity={PULSE_TREND_SEVERITIES[trend] ?? 'neutral'}
      startIcon={TrendIcon ? <TrendIcon sx={{ fontSize: 16 }} /> : undefined}
      data-testid={testId}
    />
  );
};

// The community prevalence bucket, the stronger the more platforms observe the object.
export const ThreatPulsePrevalenceChip = ({ prevalence }: { prevalence: string }) => {
  const { t_i18n } = useFormatter();
  return (
    <Chip
      label={t_i18n(PULSE_PREVALENCE_LABELS[prevalence] ?? prevalence)}
      severity={PULSE_PREVALENCE_SEVERITIES[prevalence] ?? 'neutral'}
      data-testid="threat-pulse-prevalence"
    />
  );
};

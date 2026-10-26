import { useTheme } from '@mui/material/styles';
import type { ChipSeverity } from '@filigran/design-system';
import type { Theme } from '../../../../components/Theme';

export type HealthIssueSeverity = 'critical' | 'degraded';

// Single source of how a health status looks, whatever the marker:
// chip and notifications (design system tones), tile, line and facet (theme color).
// Healthy is not here: it is never flagged, only drawn as a facet dot (see useIngestionHealthColor).
// Indexed by any status string: undefined for the ones never flagged (healthy, unknown)
export const HEALTH_DISPLAY: Record<string, {
  chip: ChipSeverity;
  color: (theme: Theme) => string | undefined;
} | undefined> = {
  critical: {
    chip: 'critical',
    color: (theme) => theme.palette.error.main,
  },
  degraded: {
    chip: 'high',
    color: (theme) => theme.palette.warn.main,
  },
};

// Theme colour of a health status, for health markers drawn outside a chip.
// Reads the project theme itself: a component holding the MUI theme lacks its extended palette (warn...)
export const useIngestionHealthColor = () => {
  const theme = useTheme<Theme>();
  return (status: string): string | undefined => {
    if (status === 'healthy') return theme.palette.success.main;
    return HEALTH_DISPLAY[status]?.color(theme);
  };
};

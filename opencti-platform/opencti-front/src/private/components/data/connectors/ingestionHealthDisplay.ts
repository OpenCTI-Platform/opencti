import { useTheme } from '@mui/material/styles';
import type { ChipSeverity } from '@filigran/design-system';
import type { Theme } from '../../../../components/Theme';

export type HealthIssueSeverity = 'critical' | 'degraded';

// Single source of how a health status looks, whatever the marker:
// chip and notifications (design system tones), tile, line and facet (theme color).
// Healthy is not here: it is never flagged, only drawn as a facet dot (see useIngestionHealthColor).
interface HealthDisplay {
  chip: ChipSeverity;
  color: (theme: Theme) => string | undefined;
}

const HEALTH_DISPLAY: Record<HealthIssueSeverity, HealthDisplay> = {
  critical: {
    chip: 'critical',
    color: (theme) => theme.palette.error.main,
  },
  degraded: {
    chip: 'high',
    color: (theme) => theme.palette.warn.main,
  },
};

// Looked up by any status or operation string: undefined for the ones never flagged (healthy, unknown) and anything else.
// Own keys only: indexing the object would also return what it inherits (constructor, toString...)
export const getHealthDisplay = (status: string): HealthDisplay | undefined => (
  Object.hasOwn(HEALTH_DISPLAY, status) ? HEALTH_DISPLAY[status as HealthIssueSeverity] : undefined
);

// Theme colour of a health status, for health markers drawn outside a chip.
// Reads the project theme itself: a component holding the MUI theme lacks its extended palette (warn...)
export const useIngestionHealthColor = () => {
  const theme = useTheme<Theme>();
  return (status: string): string | undefined => {
    if (status === 'healthy') return theme.palette.success.main;
    return getHealthDisplay(status)?.color(theme);
  };
};

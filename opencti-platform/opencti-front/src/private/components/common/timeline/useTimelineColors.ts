import { useMemo } from 'react';
import { useTheme } from '@mui/material/styles';
import type { TimelineLane } from './timelineUtils';

export interface TimelineColors {
  lanes: Record<TimelineLane, string>;
  text: string;
  textSecondary: string;
  grid: string;
  laneBackground: string;
  background: string;
  anchor: string;
  focus: string;
  shadow: string;
  fontFamily: string;
}

/** Colors of the timeline, taken from the theme so that dark and light modes and exports stay consistent. */
const useTimelineColors = (): TimelineColors => {
  const theme = useTheme();
  return useMemo(() => ({
    lanes: {
      adversary: theme.palette.error.main,
      detection: theme.palette.warning.main,
      response: theme.palette.success.main,
      evidence: theme.palette.primary.main,
      knowledge: theme.palette.secondary.main,
      custom: theme.palette.text.secondary,
    },
    text: theme.palette.text.primary,
    textSecondary: theme.palette.text.secondary,
    grid: theme.palette.divider,
    laneBackground: theme.palette.action.hover,
    background: theme.palette.background.paper,
    anchor: theme.palette.text.primary,
    focus: theme.palette.primary.main,
    shadow: theme.shadows[4],
    fontFamily: String(theme.typography.fontFamily ?? 'sans-serif'),
  }), [theme]);
};

export default useTimelineColors;

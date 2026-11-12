/**
 * Whether the legend of the graphs is open or minimized to its pill: a preference of the user,
 * shared by every graph they open in this browser, unlike the view state saved per graph.
 */
const legendPreferenceKey = (userId?: string | null) => `graph-legend-${userId || 'anonymous'}`;

export const readLegendOpen = (userId?: string | null): boolean => {
  try {
    return window.localStorage.getItem(legendPreferenceKey(userId)) !== 'minimized';
  } catch {
    return true;
  }
};

export const writeLegendOpen = (userId: string | null | undefined, open: boolean) => {
  try {
    window.localStorage.setItem(legendPreferenceKey(userId), open ? 'open' : 'minimized');
  } catch {
    // Storage refused (private mode, quota): the choice lasts until the page is left.
  }
};

import { useSyncExternalStore } from 'react';

// Below this viewport width the header has no room for a text button beside a long title and the
// "Display as" selector (the title was clipped to its first letter at 1080 px): the pivot becomes
// the framed icon button of its toolbar siblings, named by its aria-label and its tooltip.
export const XTM_PIVOT_COMPACT_QUERY = '(max-width: 1279.98px)';

const subscribeCompact = (onChange: () => void) => {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return () => {};
  const query = window.matchMedia(XTM_PIVOT_COMPACT_QUERY);
  query.addEventListener('change', onChange);
  return () => query.removeEventListener('change', onChange);
};
const readCompact = () => typeof window !== 'undefined'
  && typeof window.matchMedia === 'function'
  && window.matchMedia(XTM_PIVOT_COMPACT_QUERY).matches;
export const useCompactPivot = () => useSyncExternalStore(subscribeCompact, readCompact, () => false);

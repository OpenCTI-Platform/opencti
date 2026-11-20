import React, { useSyncExternalStore } from 'react';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';

// The connections of OpenCTI to the other XTM products live in its configuration (xtm:openaev_url,
// xtm:openaev_token, xtm:opencrq_url, xtm:opencrq_token), documented on one XTM page.
export const XTM_CONNECT_DOC_URL = 'https://docs.opencti.io/latest/deployment/configuration/#xtm-suite';

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

// A tooltip on a wrapping span: a disabled button receives no pointer events, so a tooltip anchored
// on the control itself would never show.
export const withTooltip = (title: string, control: React.ReactElement) => (
  <Tooltip>
    <TooltipTrigger asChild>
      <span style={{ display: 'inline-flex' }}>{control}</span>
    </TooltipTrigger>
    <TooltipContent>{title}</TooltipContent>
  </Tooltip>
);

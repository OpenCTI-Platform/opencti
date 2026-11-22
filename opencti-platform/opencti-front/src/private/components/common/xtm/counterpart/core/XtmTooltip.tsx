import React from 'react';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';

// A tooltip on a wrapping span: a disabled button receives no pointer events, so a tooltip anchored
// on the control itself would never show. The content is a plain label or a pivot preview card; the
// FDS Tooltip opens on hover and on keyboard focus.
export const withTooltip = (content: React.ReactNode, control: React.ReactElement) => (
  <Tooltip>
    <TooltipTrigger asChild>
      <span style={{ display: 'inline-flex' }}>{control}</span>
    </TooltipTrigger>
    <TooltipContent>{content}</TooltipContent>
  </Tooltip>
);

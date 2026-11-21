import React from 'react';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';

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

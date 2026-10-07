import React from 'react';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';

// A disabled button receives no pointer event: the reason is shown on a focusable wrapper
const DefenseDisabledReason = ({ reason, children }: { reason?: string; children: React.ReactElement }) => (reason ? (
  <Tooltip>
    <TooltipTrigger asChild>
      <span
        tabIndex={0}
        aria-label={reason}
        className="inline-flex rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-filigran-brand-primary focus-visible:ring-offset-2 focus-visible:ring-offset-focus"
      >
        {children}
      </span>
    </TooltipTrigger>
    <TooltipContent>{reason}</TooltipContent>
  </Tooltip>
) : children);

export default DefenseDisabledReason;

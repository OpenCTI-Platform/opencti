import React, { useId } from 'react';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';

// A disabled button receives no pointer event: the reason is shown on a focusable wrapper, exposed as the
// disabled action it holds (a button role makes the wrapped button presentational) and described by the reason
const DefenseDisabledReason = ({ label, reason, children }: { label: string; reason?: string; children: React.ReactElement }) => {
  const reasonId = useId();
  if (!reason) {
    return children;
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          role="button"
          tabIndex={0}
          aria-disabled="true"
          aria-label={label}
          aria-describedby={reasonId}
          className="inline-flex rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-filigran-brand-primary focus-visible:ring-offset-2 focus-visible:ring-offset-focus"
        >
          {children}
          <span id={reasonId} hidden>{reason}</span>
        </span>
      </TooltipTrigger>
      <TooltipContent>{reason}</TooltipContent>
    </Tooltip>
  );
};

export default DefenseDisabledReason;

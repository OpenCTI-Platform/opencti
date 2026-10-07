import React, { ReactNode } from 'react';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';

type DisabledReasonTooltipProps = {
  reason: string | null;
  children: ReactNode;
};

// Explains why the wrapped action is disabled; renders the action alone when there is no reason
const DisabledReasonTooltip = ({ reason, children }: DisabledReasonTooltipProps) => {
  if (!reason) {
    return <>{children}</>;
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        {/* A disabled button receives no pointer or focus events: the wrapper takes them */}
        <span tabIndex={0} style={{ display: 'inline-flex' }}>{children}</span>
      </TooltipTrigger>
      <TooltipContent>{reason}</TooltipContent>
    </Tooltip>
  );
};

export default DisabledReasonTooltip;

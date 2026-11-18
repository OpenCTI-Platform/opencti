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
        {/* FDS-WORKAROUND #68: a disabled library Button cannot trigger its own tooltip, so this span takes the hover and focus — see fds-migration/LIBRARY-FEEDBACK.md #68 */}
        {/* eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex */}
        <span tabIndex={0} style={{ display: 'inline-flex' }}>{children}</span>
      </TooltipTrigger>
      <TooltipContent>{reason}</TooltipContent>
    </Tooltip>
  );
};

export default DisabledReasonTooltip;

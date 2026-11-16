import React, { ReactNode, useId } from 'react';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';

type DisabledReasonTooltipProps = {
  reason: string | null;
  /** Name of the wrapped action: the wrapper then stands for it, announced as a disabled button saying why. */
  label?: string;
  children: ReactNode;
};

// Explains why the wrapped action is disabled; renders the action alone when there is no reason
const DisabledReasonTooltip = ({ reason, label, children }: DisabledReasonTooltipProps) => {
  const reasonId = useId();
  if (!reason) {
    return <>{children}</>;
  }
  const named = label
    ? { role: 'button', 'aria-label': label, 'aria-disabled': true, 'aria-describedby': reasonId }
    : {};
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        {/* FDS-WORKAROUND #68: a disabled library Button cannot trigger its own tooltip, so this span takes the hover and focus — see fds-migration/LIBRARY-FEEDBACK.md #68 */}
        {/* eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex */}
        <span tabIndex={0} style={{ display: 'inline-flex' }} {...named}>
          {label ? <span aria-hidden style={{ display: 'inline-flex' }}>{children}</span> : children}
          {label && <span id={reasonId} hidden>{reason}</span>}
        </span>
      </TooltipTrigger>
      <TooltipContent>{reason}</TooltipContent>
    </Tooltip>
  );
};

export default DisabledReasonTooltip;

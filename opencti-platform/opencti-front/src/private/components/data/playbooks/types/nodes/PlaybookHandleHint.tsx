import React, { type ReactElement, type ReactNode } from 'react';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import type { Position } from 'reactflow';

// The hint of a connection point: shown only where a drag from it can start, i.e. in edit mode.
export const playbookHandleHint = (canConnect: boolean, hint: string): string | undefined => (canConnect ? hint : undefined);

// What a drag from a connection point does, read on hover in edit mode. The handle stays the trigger
// itself (asChild), so React Flow still finds it under the pointer when a drag starts.
const PlaybookHandleHint = ({ hint, side, children }: { hint?: ReactNode; side: Position; children: ReactElement }) => {
  if (!hint) return children;
  return (
    <Tooltip>
      <TooltipTrigger asChild>{children}</TooltipTrigger>
      <TooltipContent side={side} style={{ maxWidth: 260 }}>{hint}</TooltipContent>
    </Tooltip>
  );
};

export default PlaybookHandleHint;

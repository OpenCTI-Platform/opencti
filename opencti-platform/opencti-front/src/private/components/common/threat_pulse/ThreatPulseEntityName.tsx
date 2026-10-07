import React from 'react';
import { Text, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';

const CLAMPED = { display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } as const;

// An entity name clamped to its row, read whole in the tooltip.
const ThreatPulseEntityName = ({ name }: { name: string }) => (
  <Tooltip>
    <TooltipTrigger asChild>
      <Text as="span" variant="content-compact" style={CLAMPED}>{name}</Text>
    </TooltipTrigger>
    <TooltipContent>{name}</TooltipContent>
  </Tooltip>
);

export default ThreatPulseEntityName;

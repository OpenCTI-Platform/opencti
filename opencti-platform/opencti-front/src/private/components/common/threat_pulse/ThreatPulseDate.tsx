import React, { CSSProperties } from 'react';
import { Text, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';

interface ThreatPulseDateProps {
  date: string;
  // A day of the community data (network first and last seen) or an instant (a refresh, a contribution).
  precision?: 'day' | 'time';
  // The sentence holding the relative date, already translated.
  format?: (relative: string) => string;
  style?: CSSProperties;
}

// A date in words relative to now, the absolute date in the tooltip.
const ThreatPulseDate = ({ date, precision = 'time', format, style }: ThreatPulseDateProps) => {
  const { rd, fld, fldt } = useFormatter();
  const relative = rd(date);
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Text as="span" variant="content-compact" style={style}>{format ? format(relative) : relative}</Text>
      </TooltipTrigger>
      <TooltipContent>{precision === 'day' ? fld(date) : fldt(date)}</TooltipContent>
    </Tooltip>
  );
};

export default ThreatPulseDate;

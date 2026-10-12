import React from 'react';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';

interface GraphRelativeTimeProps {
  date: string | Date;
  // i18n key holding a {time} placeholder, for instance "Last full pass {time}"
  template?: string;
}

/** A date written relative to now ("12 minutes ago"), the absolute date in a tooltip. */
const GraphRelativeTime = ({ date, template }: GraphRelativeTimeProps) => {
  const { t_i18n, rd, fldt } = useFormatter();
  const relative = rd(date);
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} data-testid="graph-relative-time">
          {template ? t_i18n(template, { values: { time: relative } }) : relative}
        </span>
      </TooltipTrigger>
      <TooltipContent>{fldt(date)}</TooltipContent>
    </Tooltip>
  );
};

export default GraphRelativeTime;

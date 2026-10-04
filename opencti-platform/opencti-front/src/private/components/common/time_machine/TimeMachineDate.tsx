import React from 'react';
import { Text, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';

interface TimeMachineDateProps {
  date: string;
  variant?: 'content-compact' | 'content-caption';
}

/**
 * A date of the time machine in its relative form ("3 days ago"), the absolute date in its tooltip.
 */
const TimeMachineDate = ({ date, variant = 'content-compact' }: TimeMachineDateProps) => {
  const { fldt, rd } = useFormatter();
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0}>
          <Text variant={variant}>{rd(date)}</Text>
        </span>
      </TooltipTrigger>
      <TooltipContent>{fldt(date)}</TooltipContent>
    </Tooltip>
  );
};

export default TimeMachineDate;

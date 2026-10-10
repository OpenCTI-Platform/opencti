import React from 'react';
import { Chip, type ChipSeverity, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';

export interface IngestionHealthChipProps {
  status: string;
  // Server English sentence, displayed as is
  summary: string;
  since?: string | null;
  // Extra server English lines: runtime checks, configuration warnings
  details?: ReadonlyArray<string>;
}

const severityOf = (status: string): ChipSeverity => {
  switch (status) {
    case 'critical':
      return 'critical';
    case 'degraded':
      return 'medium';
    case 'healthy':
      return 'low';
    default: // unknown, stopped, idle
      return 'neutral';
  }
};

// Runtime health of an ingestion source (RFC 0001), the summary and details in the tooltip
const IngestionHealthChip = ({ status, summary, since, details = [] }: IngestionHealthChipProps) => {
  const { t_i18n, nsdt } = useFormatter();
  const label = (() => {
    switch (status) {
      case 'healthy':
        return t_i18n('Healthy');
      case 'idle':
        return t_i18n('Idle');
      case 'degraded':
        return t_i18n('Degraded');
      case 'critical':
        return t_i18n('Critical');
      case 'stopped':
        return t_i18n('Stopped');
      default:
        return t_i18n('Unknown');
    }
  })();
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Chip label={label} severity={severityOf(status)} tabIndex={0} data-testid="ingestion-health-chip" />
      </TooltipTrigger>
      <TooltipContent>
        <div>{summary}</div>
        {since && <div>{`${t_i18n('Since')} ${nsdt(since)}`}</div>}
        {details.map((line) => <div key={line}>{line}</div>)}
      </TooltipContent>
    </Tooltip>
  );
};

export default IngestionHealthChip;

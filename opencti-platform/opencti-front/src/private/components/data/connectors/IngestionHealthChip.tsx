import React from 'react';
import { Chip, type ChipSeverity, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import useHelper from '../../../../utils/hooks/useHelper';
import { capitalizeFirstLetter } from '../../../../utils/String';

interface IngestionHealthCheck {
  readonly health_check_code: string;
  readonly health_check_message?: string | null;
}

export interface IngestionHealthData {
  readonly status: string;
  readonly status_since: string;
  readonly healthChecks: ReadonlyArray<IngestionHealthCheck>;
}

interface IngestionHealthChipProps {
  // Null until the manager first evaluates the ingestion
  ingestionHealth?: IngestionHealthData | null;
}

// Design system feedback tones
const HEALTH_STATUS_SEVERITY_COLORS: Record<string, ChipSeverity> = {
  critical: 'critical',
  degraded: 'high',
  healthy: 'low',
  stopped: 'neutral',
  unknown: 'neutral',
};

const IngestionHealthChip: React.FC<IngestionHealthChipProps> = ({ ingestionHealth }) => {
  const { t_i18n, nsdt } = useFormatter();
  const { isFeatureEnable } = useHelper();
  if (!isFeatureEnable('INGESTION_HEALTH')) {
    return null;
  }
  const status = ingestionHealth?.status ?? 'unknown';
  const checks = ingestionHealth?.healthChecks ?? [];
  let emptyMessage = t_i18n('No health issue detected');
  if (!ingestionHealth) {
    emptyMessage = t_i18n('Not evaluated yet');
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        {/* eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex */}
        <span tabIndex={0} style={{ display: 'inline-flex' }}>
          <Chip label={t_i18n(capitalizeFirstLetter(status))} severity={HEALTH_STATUS_SEVERITY_COLORS[status] ?? 'neutral'} />
        </span>
      </TooltipTrigger>
      <TooltipContent>
        {ingestionHealth && <div>{`${t_i18n('Since')} ${nsdt(ingestionHealth.status_since)}`}</div>}
        {checks.length > 0
          ? checks.map((check) => <div key={check.health_check_code}>{check.health_check_message ?? check.health_check_code}</div>)
          : <div>{emptyMessage}</div>}
      </TooltipContent>
    </Tooltip>
  );
};

export default IngestionHealthChip;

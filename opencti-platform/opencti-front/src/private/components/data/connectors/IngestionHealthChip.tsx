import React from 'react';
import { graphql, useFragment } from 'react-relay';
import { Chip, type ChipSeverity, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import useHelper from '../../../../utils/hooks/useHelper';
import { capitalizeFirstLetter } from '../../../../utils/String';
import type { IngestionHealthChip_ingestionHealth$key } from './__generated__/IngestionHealthChip_ingestionHealth.graphql';

// Spread in every query showing the health of a connector, a feed or a sync
const ingestionHealthFragment = graphql`
  fragment IngestionHealthChip_ingestionHealth on IngestionHealth {
    status
    status_since
    healthChecks {
      health_check_code
      health_check_message
    }
  }
`;

interface IngestionHealthChipProps {
  // Null until the manager first evaluates the ingestion
  ingestionHealth?: IngestionHealthChip_ingestionHealth$key | null;
}

// Design system feedback tones
const HEALTH_STATUS_SEVERITY_COLORS: Record<string, ChipSeverity> = {
  critical: 'critical',
  degraded: 'high',
  healthy: 'low',
  unknown: 'neutral',
};

const IngestionHealthChip: React.FC<IngestionHealthChipProps> = ({ ingestionHealth: ingestionHealthKey }) => {
  const { t_i18n, nsdt } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const ingestionHealth = useFragment(ingestionHealthFragment, ingestionHealthKey ?? null);
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

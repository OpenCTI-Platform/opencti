import React from 'react';
import { Chip, type ChipSeverity, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import useHelper from '../../../../utils/hooks/useHelper';
import { capitalizeFirstLetter } from '../../../../utils/String';

interface IngestionHealthCheck {
  readonly health_check_code: string;
  readonly health_check_message?: string | null;
}

interface IngestionHealthChipProps {
  healthStatus?: string | null;
  healthStatusSince?: string | null;
  healthChecks?: ReadonlyArray<IngestionHealthCheck> | null;
}

const IngestionHealthChip: React.FC<IngestionHealthChipProps> = ({ healthStatus, healthStatusSince, healthChecks }) => {
  const { t_i18n, nsdt } = useFormatter();
  const { isFeatureEnable } = useHelper();
  if (!isFeatureEnable('INGESTION_HEALTH')) {
    return null;
  }
  const status = healthStatus ?? 'unknown';
  const checks = healthChecks ?? [];
  let emptyMessage = t_i18n('No health issue detected');
  if (!healthStatusSince) {
    emptyMessage = t_i18n('Not evaluated yet');
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} style={{ display: 'inline-flex' }}>
          <Chip label={t_i18n(capitalizeFirstLetter(status))} severity={status as ChipSeverity} />
        </span>
      </TooltipTrigger>
      <TooltipContent>
        {healthStatusSince && <div>{`${t_i18n('Since')} ${nsdt(healthStatusSince)}`}</div>}
        {checks.length > 0
          ? checks.map((check) => <div key={check.health_check_code}>{check.health_check_message ?? check.health_check_code}</div>)
          : <div>{emptyMessage}</div>}
      </TooltipContent>
    </Tooltip>
  );
};

export default IngestionHealthChip;

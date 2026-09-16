import React from 'react';
import { useTheme } from '@mui/material/styles';
import Tag from '@common/tag/Tag';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { countHealthStatuses } from '../../../../utils/IngestionHealth';

interface IngestionHealthCountersProps {
  connectors: ReadonlyArray<{ ingestion_health?: { status?: string | null } | null }>;
}

// The line an administrator reads each morning, above the table.
//
// Silent when nothing is wrong: a permanent "0 critical" badge is noise, and
// the table below already says everything is fine.
const IngestionHealthCounters: React.FC<IngestionHealthCountersProps> = ({ connectors }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const counts = countHealthStatuses(connectors);

  const entries = [
    { key: 'critical', value: counts.critical, color: theme.palette.error.main, label: t_i18n('Critical') },
    { key: 'degraded', value: counts.degraded, color: theme.palette.warn.main, label: t_i18n('Degraded') },
    // Stopped is deliberate, so it is listed without a colour: worth knowing,
    // not worth alarming about.
    { key: 'stopped', value: counts.stopped, color: undefined, label: t_i18n('Stopped') },
  ].filter((entry) => entry.value > 0);

  if (entries.length === 0) {
    return null;
  }

  return (
    <div style={{ display: 'flex', gap: 8, alignItems: 'center', paddingBottom: 12 }}>
      {entries.map((entry) => (
        <Tag key={entry.key} label={`${entry.value} ${entry.label}`} color={entry.color} />
      ))}
    </div>
  );
};

export default IngestionHealthCounters;

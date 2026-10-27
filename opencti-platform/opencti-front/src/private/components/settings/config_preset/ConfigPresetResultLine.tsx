import React, { FunctionComponent } from 'react';
import { Chip, Text } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

export type ConfigPresetResultStatus = 'CREATED' | 'OVERWRITTEN' | 'SKIPPED' | 'FAILED';

interface ConfigPresetResultLineProps {
  // Absent when the line is shown on the row of the item, which already has its label
  label?: string;
  status: ConfigPresetResultStatus | string;
  // Shown as the backend returns it (English, not translated)
  reason?: string | null;
}

const STATUS_LABELS: Record<ConfigPresetResultStatus, string> = {
  CREATED: 'Created',
  OVERWRITTEN: 'Overwritten',
  SKIPPED: 'Skipped',
  FAILED: 'Failed',
};

const STATUS_SEVERITIES = {
  CREATED: 'low',
  OVERWRITTEN: 'info',
  SKIPPED: 'neutral',
  FAILED: 'critical',
} as const;

// The result of an item of an import: its status and the reason
const ConfigPresetResultLine: FunctionComponent<ConfigPresetResultLineProps> = ({ label, status, reason }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const known = status in STATUS_LABELS;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }}>
      {label && <Text variant="content-base">{label}</Text>}
      <Chip
        label={known ? t_i18n(STATUS_LABELS[status as ConfigPresetResultStatus]) : status}
        severity={known ? STATUS_SEVERITIES[status as ConfigPresetResultStatus] : 'neutral'}
      />
      {reason && <Text variant="content-compact" style={{ color: theme.palette.text.secondary }}>{reason}</Text>}
    </div>
  );
};

export default ConfigPresetResultLine;

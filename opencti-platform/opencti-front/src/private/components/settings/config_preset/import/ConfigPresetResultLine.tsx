import React, { FunctionComponent } from 'react';
import { Chip, Text } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';

export type ConfigPresetResultStatus = 'CREATED' | 'OVERWRITTEN' | 'SKIPPED' | 'FAILED';

interface ConfigPresetResultLineProps {
  // Absent when the line is shown on the row of the item, which already has its label
  label?: string;
  status: ConfigPresetResultStatus | string;
  // The English sentence of the backend: translated when it is a known one, shown as is otherwise
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

type Translate = ReturnType<typeof useFormatter>['t_i18n'];

// The reasons are sentences of the backend (the API exposes them as text), so they are matched here to be translated
const translateReason = (t_i18n: Translate, reason: string) => {
  switch (reason) {
    case 'Already exists': return t_i18n('Already exists');
    case 'Nothing to import': return t_i18n('Nothing to import');
    case 'Enterprise Edition required': return t_i18n('Enterprise Edition required');
    case 'Unexpected item id': return t_i18n('Unexpected item id');
    case 'Unknown message': return t_i18n('Unknown message');
    case 'The standard id of the theme does not match its id': return t_i18n('The standard id of the theme does not match its id');
    case 'The standard id of the theme is required to overwrite it': return t_i18n('The standard id of the theme is required to overwrite it');
    case 'Built-in theme': return t_i18n('Built-in theme');
    case 'Theme already exists': return t_i18n('Theme already exists');
    case 'Theme name already exists': return t_i18n('Theme name already exists');
    default: break;
  }
  const copyName = reason.match(/^Added as "(.+)"$/)?.[1];
  if (copyName) {
    return t_i18n('Added as "{name}"', { values: { name: copyName } });
  }
  const defaultThemeName = reason.match(/^Default theme (.+) could not be imported$/)?.[1];
  if (defaultThemeName) {
    return t_i18n('Default theme {name} could not be imported', { values: { name: defaultThemeName } });
  }
  return reason;
};

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
      {reason && <Text variant="content-compact" style={{ color: theme.palette.text.secondary }}>{translateReason(t_i18n, reason)}</Text>}
    </div>
  );
};

export default ConfigPresetResultLine;

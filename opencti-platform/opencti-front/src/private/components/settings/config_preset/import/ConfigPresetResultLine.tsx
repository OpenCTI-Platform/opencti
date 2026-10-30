import React, { FunctionComponent } from 'react';
import { CheckCircleOutlined } from '@mui/icons-material';
import { Chip, Text } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import { translateConfigPresetEntityTypes } from '../configPresetEntityTypes';

export type ConfigPresetResultStatus = 'CREATED' | 'OVERWRITTEN' | 'SKIPPED' | 'FAILED';

interface ConfigPresetResultLineProps {
  // Absent when the line is shown on the row of the item, which already has its label
  label?: string;
  status: ConfigPresetResultStatus | string;
  // The English sentence of the backend: translated when it is a known one, shown as is otherwise
  reason?: string | null;
  // The item went well: a tick leads the line
  isDone?: boolean;
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
    case 'Unexpected item id': return t_i18n('Unexpected item id');
    case 'Unknown message': return t_i18n('Unknown message');
    case 'The standard id of the theme does not match its id': return t_i18n('The standard id of the theme does not match its id');
    case 'The standard id of the theme is required to overwrite it': return t_i18n('The standard id of the theme is required to overwrite it');
    case 'Built-in theme': return t_i18n('Built-in theme');
    case 'Theme already exists': return t_i18n('Theme already exists');
    case 'Theme name already exists': return t_i18n('Theme name already exists');
    case 'The standard id of the role does not match its name': return t_i18n('The standard id of the role does not match its name');
    case 'Role already exists': return t_i18n('Role already exists');
    case 'Role name already exists': return t_i18n('Role name already exists');
    case 'The Administrator role keeps the bypass capability': return t_i18n('The Administrator role keeps the bypass capability');
    case 'Grants sensitive rights': return t_i18n('Grants sensitive rights');
    default: break;
  }
  const unknownCapabilities = reason.match(/^Unknown capabilities: (.+)$/)?.[1];
  if (unknownCapabilities) {
    return t_i18n('Unknown capabilities: {capabilities}', { values: { capabilities: unknownCapabilities } });
  }
  const draftCapabilities = reason.match(/^Capabilities not available in draft: (.+)$/)?.[1];
  if (draftCapabilities) {
    return t_i18n('Capabilities not available in draft: {capabilities}', { values: { capabilities: draftCapabilities } });
  }
  const copyName = reason.match(/^Added as "(.+)"$/)?.[1];
  if (copyName) {
    return t_i18n('Added as "{name}"', { values: { name: copyName } });
  }
  const hiddenTypes = reason.match(/^Entity types that cannot be hidden: (.+)$/)?.[1];
  if (hiddenTypes) {
    return t_i18n('Entity types that cannot be hidden: {types}', { values: { types: hiddenTypes } });
  }
  const shownTypes = reason.match(/^Entity types shown again: (.+)$/)?.[1];
  if (shownTypes) {
    return t_i18n('Entity types shown again: {types}', { values: { types: translateConfigPresetEntityTypes(t_i18n, shownTypes) } });
  }
  const defaultThemeName = reason.match(/^Default theme (.+) could not be imported$/)?.[1];
  if (defaultThemeName) {
    return t_i18n('Default theme {name} could not be imported', { values: { name: defaultThemeName } });
  }
  return reason;
};

// The result of an item of an import: its status and the reason
const ConfigPresetResultLine: FunctionComponent<ConfigPresetResultLineProps> = ({ label, status, reason, isDone = false }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const known = status in STATUS_LABELS;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }}>
      {isDone && <CheckCircleOutlined aria-hidden data-testid="config-preset-result-tick" fontSize="small" style={{ color: theme.palette.success.main }} />}
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

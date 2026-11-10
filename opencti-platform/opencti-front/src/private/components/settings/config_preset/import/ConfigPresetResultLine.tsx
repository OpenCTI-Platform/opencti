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
  // The code of the importer behind the reason: what the line shows depends on it, not on the text
  code?: string | null;
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

// An item the platform has as it is: skipped, but said without the status, which would read as if something was ignored
export const CODE_UNCHANGED = 'unchanged';

type Translate = ReturnType<typeof useFormatter>['t_i18n'];

// The reasons are sentences of the backend (the API exposes them as text), so they are matched here to be translated
const translateReason = (t_i18n: Translate, reason: string) => {
  switch (reason) {
    case 'Already exists': return t_i18n('Already exists');
    case 'Already up to date': return t_i18n('Already up to date');
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
    case 'Removes sensitive rights': return t_i18n('Removes sensitive rights');
    case 'Marking already exists': return t_i18n('Marking already exists');
    case 'The standard id of the marking does not match its definition': return t_i18n('The standard id of the marking does not match its definition');
    case 'The order of the marking changes': return t_i18n('The order of the marking changes');
    case 'Groups that get new markings automatically get this one': return t_i18n('Groups that get new markings automatically get this one');
    case 'The expiration date of the users\' passwords changes': return t_i18n('The expiration date of the users\' passwords changes');
    case 'The users\' passwords no longer expire': return t_i18n('The users\' passwords no longer expire');
    case 'Users can view the users of other organizations': return t_i18n('Users can view the users of other organizations');
    case 'The standard id of the group does not match its name': return t_i18n('The standard id of the group does not match its name');
    case 'Group already exists': return t_i18n('Group already exists');
    case 'Group name already exists': return t_i18n('Group name already exists');
    case 'New users join this group automatically': return t_i18n('New users join this group automatically');
    case 'New integration users join this group automatically': return t_i18n('New integration users join this group automatically');
    case 'The main organization requires the Enterprise Edition': return t_i18n('The main organization requires the Enterprise Edition');
    case 'Requires the right to manage the sensitive configuration': return t_i18n('Requires the right to manage the sensitive configuration');
    case 'The Administrators group keeps the Administrator role': return t_i18n('The Administrators group keeps the Administrator role');
    case 'Requires Enterprise Edition': return t_i18n('Requires Enterprise Edition');
    case 'The password policy cannot be satisfied: its maximum length is below what its other rules require':
      return t_i18n('The password policy cannot be satisfied: its maximum length is below what its other rules require');
    default: break;
  }
  const mainOrganization = reason.match(/^Sets the main organization: (.+)$/)?.[1];
  if (mainOrganization) {
    return t_i18n('Sets the main organization: {name}', { values: { name: mainOrganization } });
  }
  const missingOrganization = reason.match(/^Main organization not found: (.+)$/)?.[1];
  if (missingOrganization) {
    return t_i18n('Main organization not found: {name}', { values: { name: missingOrganization } });
  }
  const missingRoles = reason.match(/^Roles could not be imported: (.+)$/)?.[1];
  if (missingRoles) {
    return t_i18n('Roles could not be imported: {roles}', { values: { roles: missingRoles } });
  }
  const missingMarkings = reason.match(/^Markings not found: (.+)$/)?.[1];
  if (missingMarkings) {
    return t_i18n('Markings not found: {markings}', { values: { markings: missingMarkings } });
  }
  const removedRoles = reason.match(/^Roles removed: (.+)$/)?.[1];
  if (removedRoles) {
    return t_i18n('Roles removed: {roles}', { values: { roles: removedRoles } });
  }
  const removedMarkings = reason.match(/^Markings removed: (.+)$/)?.[1];
  if (removedMarkings) {
    return t_i18n('Markings removed: {markings}', { values: { markings: removedMarkings } });
  }
  const notAllowedShareable = reason.match(/^Shareable markings not allowed by the group: (.+)$/)?.[1];
  if (notAllowedShareable) {
    return t_i18n('Shareable markings not allowed by the group: {markings}', { values: { markings: notAllowedShareable } });
  }
  const missingDashboard = reason.match(/^Default dashboard not found: (.+)$/)?.[1];
  if (missingDashboard) {
    return t_i18n('Default dashboard not found: {name}', { values: { name: missingDashboard } });
  }
  const unknownCapabilities = reason.match(/^Unknown capabilities: (.+)$/)?.[1];
  if (unknownCapabilities) {
    return t_i18n('Unknown capabilities: {capabilities}', { values: { capabilities: unknownCapabilities } });
  }
  const draftCapabilities = reason.match(/^Capabilities not available in draft: (.+)$/)?.[1];
  if (draftCapabilities) {
    return t_i18n('Capabilities not available in draft: {capabilities}', { values: { capabilities: draftCapabilities } });
  }
  const removedCapabilities = reason.match(/^Capabilities removed: (.+)$/)?.[1];
  if (removedCapabilities) {
    return t_i18n('Capabilities removed: {capabilities}', { values: { capabilities: removedCapabilities } });
  }
  const removedDraftCapabilities = reason.match(/^Capabilities in draft removed: (.+)$/)?.[1];
  if (removedDraftCapabilities) {
    return t_i18n('Capabilities in draft removed: {capabilities}', { values: { capabilities: removedDraftCapabilities } });
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

const translateReasons = (t_i18n: Translate, reason: string) => reason.split('\n').map((part) => translateReason(t_i18n, part)).join(' · ');

// The result of an item of an import: its status and the reason
const ConfigPresetResultLine: FunctionComponent<ConfigPresetResultLineProps> = ({ label, status, reason, code, isDone = false }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const known = status in STATUS_LABELS;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }}>
      {isDone && <CheckCircleOutlined aria-hidden data-testid="config-preset-result-tick" fontSize="small" style={{ color: theme.palette.success.main }} />}
      {label && <Text variant="content-base">{label}</Text>}
      {code !== CODE_UNCHANGED && (
        <Chip
          label={known ? t_i18n(STATUS_LABELS[status as ConfigPresetResultStatus]) : status}
          severity={known ? STATUS_SEVERITIES[status as ConfigPresetResultStatus] : 'neutral'}
        />
      )}
      {reason && <Text variant="content-compact" style={{ color: theme.palette.text.secondary }}>{translateReasons(t_i18n, reason)}</Text>}
    </div>
  );
};

export default ConfigPresetResultLine;

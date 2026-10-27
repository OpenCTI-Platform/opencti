import React, { FunctionComponent } from 'react';
import { Alert, Text } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';

interface ConfigPresetImportMessagesProps {
  itemsCount: number;
  // The simulation results are out of date after a change of the selection
  isOutdated: boolean;
  hasPlatformChanged: boolean;
  isOtherImportRunning: boolean;
  startedBy?: string | null;
}

// What the admin reads above the actions of the preview: the compatibility of the bundle, who blocks Apply, the state of the selection
const ConfigPresetImportMessages: FunctionComponent<ConfigPresetImportMessagesProps> = ({
  itemsCount,
  isOutdated,
  hasPlatformChanged,
  isOtherImportRunning,
  startedBy,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  let hint = '';
  if (hasPlatformChanged) {
    hint = t_i18n('The platform changed since your simulation');
  } else if (isOutdated) {
    hint = t_i18n('Simulate again to update');
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(2) }}>
      <Alert
        severity="success"
        elevation={1}
        title={t_i18n('{count} items. Compatible with your OpenCTI version.', { values: { count: itemsCount } })}
      />
      {isOtherImportRunning && <Text variant="content-compact">{t_i18n('Apply is available once the import in progress is over.')}</Text>}
      {startedBy && <Text variant="content-compact">{t_i18n('Started by {name}', { values: { name: startedBy } })}</Text>}
      {hint && <Text variant="content-compact">{hint}</Text>}
    </div>
  );
};

export default ConfigPresetImportMessages;

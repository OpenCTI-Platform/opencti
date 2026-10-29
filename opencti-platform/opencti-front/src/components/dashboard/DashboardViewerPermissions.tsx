import { Switch } from '@filigran/design-system';
import Stack from '@mui/material/Stack';
import { useFormatter } from '../i18n';
import type { DashboardConfig } from './dashboard-types';

type ViewerPermissions = Pick<DashboardConfig, 'allowViewersToEditTimeFilters' | 'allowViewersToChangeVariables'>;

interface DashboardViewerPermissionsProps {
  config: DashboardConfig;
  // Reports the switched key only: the caller merges it into the dashboard config.
  onChange: (patch: ViewerPermissions) => void;
}

/**
 * What a viewer of the dashboard may change for themselves. None of these grants any right to write the dashboard.
 */
const DashboardViewerPermissions = ({ config, onChange }: DashboardViewerPermissionsProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Stack sx={{ marginTop: '20px', gap: 1 }}>
      <Switch
        name="allowViewersToEditTimeFilters"
        checked={config.allowViewersToEditTimeFilters === true}
        label={t_i18n('Allow viewers to edit time filters')}
        onCheckedChange={(checked: boolean) => onChange({ allowViewersToEditTimeFilters: checked })}
      />
      <Switch
        name="allowViewersToChangeVariables"
        checked={config.allowViewersToChangeVariables === true}
        label={t_i18n('Allow viewers to change variable values')}
        onCheckedChange={(checked: boolean) => onChange({ allowViewersToChangeVariables: checked })}
      />
    </Stack>
  );
};

export default DashboardViewerPermissions;

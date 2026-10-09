import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { Input } from '@filigran/design-system';
import Alert from '@mui/material/Alert';
import Divider from '@mui/material/Divider';
import DownloadOutlined from '@mui/icons-material/DownloadOutlined';
import WarningAmberOutlined from '@mui/icons-material/WarningAmberOutlined';
import { useTheme } from '@mui/styles';
import Button from '@common/button/Button';
import { useFormatter } from 'src/components/i18n';
import type { Theme } from 'src/components/Theme';
import Drawer from '@components/common/drawer/Drawer';
import { APP_BASE_PATH } from '../../../../../relay/environment';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { EXPORT_CATEGORIES, getDefaultCheckedCategoryItems } from './globalExportBundleDrawer-utils';
import ExportBundleInstancesAccordion, { InstanceSelectionMode } from './ExportBundleInstancesAccordion';
import ExportBundleCategoryChecklist from './ExportBundleCategoryChecklist';
import { EXPORT_INSTANCE_CONFIGS } from './exportBundleInstances';
import {
  PlatformBundleDrawerExportMutation,
  PlatformBundleDrawerExportMutation$data,
} from '@components/settings/experience/globalExportBundle/__generated__/PlatformBundleDrawerExportMutation.graphql';

const platformBundleDrawerExportMutation = graphql`
  mutation PlatformBundleDrawerExportMutation($entityTypes: [String!]!, $selections: [GlobalExportSelectionInput!], $bundleName: String) {
    globalConfigurationExport(entityTypes: $entityTypes, selections: $selections, bundleName: $bundleName) {
      id
    }
  }
`;

const getDefaultInstanceModes = (): Record<string, InstanceSelectionMode> => Object.fromEntries(
  EXPORT_INSTANCE_CONFIGS.map((config) => [config.entityType, 'all' as InstanceSelectionMode]),
);

interface GlobalExportBundleDrawerProps {
  open: boolean;
  onClose: () => void;
}

const GlobalExportBundleDrawer: FunctionComponent<GlobalExportBundleDrawerProps> = ({ open, onClose }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const [checkedCategoryItems, setCheckedCategoryItems] = useState<Record<string, string[]>>(getDefaultCheckedCategoryItems());
  const [instanceModes, setInstanceModes] = useState<Record<string, InstanceSelectionMode>>(getDefaultInstanceModes());
  const [instanceSelectedIds, setInstanceSelectedIds] = useState<Record<string, string[]>>({});
  const [bundleName, setBundleName] = useState('');
  const [commitExportMutation, exporting] = useApiMutation<PlatformBundleDrawerExportMutation>(platformBundleDrawerExportMutation);

  const handleInstanceModeChange = (entityType: string) => (mode: InstanceSelectionMode) => {
    setInstanceModes((prev) => ({ ...prev, [entityType]: mode }));
  };

  const handleToggleInstanceId = (entityType: string) => (id: string, checked: boolean) => {
    setInstanceSelectedIds((prev) => {
      const current = prev[entityType] ?? [];
      const next = checked
        ? [...current, id]
        : current.filter((existingId) => existingId !== id);
      return { ...prev, [entityType]: next };
    });
  };

  const handleToggleCategoryItem = (categoryKey: string, itemKey: string) => (checked: boolean | 'indeterminate') => {
    setCheckedCategoryItems((prev) => {
      const current = prev[categoryKey] ?? [];
      return {
        ...prev,
        [categoryKey]: checked === true ? [...current, itemKey] : current.filter((k) => k !== itemKey),
      };
    });
  };

  const entityTypes = Object.values(checkedCategoryItems).flat();
  const selections: { entityType: string; ids: string[] }[] = [];

  EXPORT_INSTANCE_CONFIGS.forEach((config) => {
    const mode = instanceModes[config.entityType] ?? 'all';
    const ids = instanceSelectedIds[config.entityType] ?? [];
    if (mode === 'all') {
      entityTypes.push(config.entityType);
    } else if (mode === 'partial' && ids.length > 0) {
      entityTypes.push(config.entityType);
      selections.push({ entityType: config.entityType, ids });
    }
  });

  const onExport = () => {
    commitExportMutation({
      variables: { entityTypes, selections, bundleName },
      onCompleted: (result: PlatformBundleDrawerExportMutation$data) => {
        const fileId = result?.globalConfigurationExport?.id;
        if (fileId) {
          window.location.href = `${APP_BASE_PATH}/storage/get/${encodeURIComponent(fileId)}`;
        }
        onClose();
      },
    });
  };

  const accordionSx = {
    backgroundColor: 'transparent',
    boxShadow: 'none',
    border: `1px solid ${theme.palette.divider}`,
    '&:before': { display: 'none' },
  };

  return (
    <Drawer
      title={t_i18n('Platform Bundle')}
      open={open}
      onClose={onClose}
      size="medium"
      containerStyle={{ padding: 0, gap: 0, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}
    >
      {({ onClose: handleClose }) => (
        <>
          <Box sx={{ flexGrow: 1, overflowY: 'auto', p: 3, display: 'flex', flexDirection: 'column', gap: 2 }}>
            <Typography variant="body2" color="textSecondary">
              {t_i18n('Select all the elements to include in your configuration bundle')}
            </Typography>

            {EXPORT_INSTANCE_CONFIGS.map((config, index) => {
              const previousGroup = index > 0 ? EXPORT_INSTANCE_CONFIGS[index - 1].group : undefined;
              const showGroupHeader = config.group && config.group !== previousGroup;
              return (
                <React.Fragment key={config.entityType}>
                  {showGroupHeader && (
                    <Typography variant="overline" color="textSecondary" sx={{ mt: 1 }}>
                      {t_i18n(config.group)}
                    </Typography>
                  )}
                  <ExportBundleInstancesAccordion
                    config={config}
                    mode={instanceModes[config.entityType] ?? 'all'}
                    selectedIds={instanceSelectedIds[config.entityType] ?? []}
                    onModeChange={handleInstanceModeChange(config.entityType)}
                    onToggleId={handleToggleInstanceId(config.entityType)}
                    accordionSx={accordionSx}
                  />
                </React.Fragment>
              );
            })}

            {EXPORT_CATEGORIES.map((category, index) => {
              const previousGroup = index > 0
                ? EXPORT_CATEGORIES[index - 1].label
                : EXPORT_INSTANCE_CONFIGS[EXPORT_INSTANCE_CONFIGS.length - 1]?.group;
              return (
                <ExportBundleCategoryChecklist
                  key={category.key}
                  category={category}
                  checkedKeys={checkedCategoryItems[category.key] ?? []}
                  showLabel={category.label !== previousGroup}
                  onToggleItem={(itemKey) => handleToggleCategoryItem(category.key, itemKey)}
                  accordionSx={accordionSx}
                />
              );
            })}

            <Alert
              icon={<WarningAmberOutlined fontSize="inherit" />}
              severity="warning"
              variant="outlined"
            >
              <Typography>{t_i18n('Credentials handling')}</Typography>
              <Typography variant="body2">
                {t_i18n('Sensitive credentials will not be included in the export bundle. After import:')}
              </Typography>
              <Box component="ul" sx={{ m: 0, pl: 2.5 }}>
                <li>{t_i18n('Connectors and integrations will remain inactive')}</li>
                <li>{t_i18n('Reconfigure API keys/passwords manually')}</li>
              </Box>
            </Alert>

            <Input
              label={t_i18n('Bundle name')}
              value={bundleName}
              onChange={(e) => setBundleName(e.target.value)}
            />
          </Box>
          <Divider />
          <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 1.5, p: 3 }}>
            <Button variant="secondary" onClick={handleClose}>
              {t_i18n('Cancel')}
            </Button>
            <Button
              startIcon={<DownloadOutlined />}
              disabled={exporting || entityTypes.length === 0}
              onClick={onExport}
            >
              {t_i18n('Export Platform Bundle')}
            </Button>
          </Box>
        </>
      )}
    </Drawer>
  );
};

export default GlobalExportBundleDrawer;

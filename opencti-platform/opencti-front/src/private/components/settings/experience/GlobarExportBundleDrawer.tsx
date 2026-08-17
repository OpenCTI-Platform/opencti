import React, { FunctionComponent, useState, ChangeEvent } from 'react';
import { graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import Checkbox from '@mui/material/Checkbox';
import FormControlLabel from '@mui/material/FormControlLabel';
import TextField from '@mui/material/TextField';
import Alert from '@mui/material/Alert';
import Divider from '@mui/material/Divider';
import ExpandMoreOutlined from '@mui/icons-material/ExpandMoreOutlined';
import DownloadOutlined from '@mui/icons-material/DownloadOutlined';
import WarningAmberOutlined from '@mui/icons-material/WarningAmberOutlined';
import fileDownload from 'js-file-download';
import { useTheme } from '@mui/styles';
import Button from '@common/button/Button';
import { useFormatter } from 'src/components/i18n';
import type { Theme } from 'src/components/Theme';
import Drawer from '@components/common/drawer/Drawer';
import { fetchQuery } from '../../../../relay/environment';
import { EXPORT_CATEGORIES, getDefaultCheckedCategoryItems } from './globalExportBundleDrawer-utils';
import ExportBundleInstancesAccordion, { InstanceSelectionMode } from './ExportBundleInstancesAccordion';
import { EXPORT_INSTANCE_CONFIGS } from './exportBundleInstances';
import type { PlatformBundleDrawerExportQuery$data } from './__generated__/PlatformBundleDrawerExportQuery.graphql';

const platformBundleDrawerExportQuery = graphql`
  query PlatformBundleDrawerExportQuery($entityTypes: [String!]!, $selections: [GlobalExportSelectionInput!]) {
    globalConfigurationExport(entityTypes: $entityTypes, selections: $selections)
  }
`;

const getDefaultInstanceModes = (): Record<string, InstanceSelectionMode> => Object.fromEntries(
  EXPORT_INSTANCE_CONFIGS.map((config) => [config.entityType, 'all' as InstanceSelectionMode]),
);

const base64ToBytes = (base64: string): Uint8Array<ArrayBuffer> => {
  const binary = atob(base64);
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

interface GlobalExportBundleDrawerProps {
  open: boolean;
  onClose: () => void;
}

const GlobalExportBundleDrawer: FunctionComponent<GlobalExportBundleDrawerProps> = ({ open, onClose }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const [checkedCategoryItems, setCheckedCategoryItems] = useState<Record<string, string[]>>(getDefaultCheckedCategoryItems());
  const [instanceModes, setInstanceModes] = useState<Record<string, InstanceSelectionMode>>(getDefaultInstanceModes());
  const [instanceSelectedIds, setInstanceSelectedIds] = useState<Record<string, Set<string>>>({});
  const [bundleName, setBundleName] = useState('');
  const [exporting, setExporting] = useState(false);

  const handleInstanceModeChange = (entityType: string) => (mode: InstanceSelectionMode) => {
    setInstanceModes((prev) => ({ ...prev, [entityType]: mode }));
  };

  const handleToggleInstanceId = (entityType: string) => (id: string, checked: boolean) => {
    setInstanceSelectedIds((prev) => {
      const next = new Set(prev[entityType] ?? []);
      if (checked) next.add(id);
      else next.delete(id);
      return { ...prev, [entityType]: next };
    });
  };

  const handleToggleFlatCategory = (categoryKey: string) => (event: ChangeEvent<HTMLInputElement>) => {
    setCheckedCategoryItems((prev) => ({ ...prev, [categoryKey]: event.target.checked ? [categoryKey] : [] }));
  };

  const handleToggleCategoryAll = (categoryKey: string, allKeys: string[]) => (event: ChangeEvent<HTMLInputElement>) => {
    setCheckedCategoryItems((prev) => ({ ...prev, [categoryKey]: event.target.checked ? allKeys : [] }));
  };

  const handleToggleCategoryItem = (categoryKey: string, itemKey: string) => (event: ChangeEvent<HTMLInputElement>) => {
    setCheckedCategoryItems((prev) => {
      const current = prev[categoryKey] ?? [];
      return {
        ...prev,
        [categoryKey]: event.target.checked ? [...current, itemKey] : current.filter((k) => k !== itemKey),
      };
    });
  };

  const exportConfiguration = async () => {
    const entityTypes = Array.from(new Set(Object.values(checkedCategoryItems).flat()));
    const selections: { entityType: string; ids: string[] }[] = [];

    EXPORT_INSTANCE_CONFIGS.forEach((config) => {
      const mode = instanceModes[config.entityType] ?? 'all';
      const ids = instanceSelectedIds[config.entityType] ?? new Set<string>();
      if (mode === 'all') {
        entityTypes.push(config.entityType);
      } else if (mode === 'partial' && ids.size > 0) {
        entityTypes.push(config.entityType);
        selections.push({ entityType: config.entityType, ids: Array.from(ids) });
      }
    });

    setExporting(true);
    try {
      const result = await fetchQuery(
        platformBundleDrawerExportQuery,
        { entityTypes: Array.from(new Set(entityTypes)), selections },
      ).toPromise() as PlatformBundleDrawerExportQuery$data;
      if (result?.globalConfigurationExport) {
        const blob = new Blob([base64ToBytes(result.globalConfigurationExport)], { type: 'application/zip' });
        const safeBundleName = bundleName.trim().replace(/[^a-z0-9-_]+/gi, '_').replace(/^_+|_+$/g, '').slice(0, 80);
        const suffix = safeBundleName ? `_${safeBundleName}` : '';
        const [day, month, year] = new Date().toLocaleDateString('fr-FR').split('/');
        fileDownload(blob, `${year}${month}${day}_opencti_config_export${suffix}.zip`);
      }
    } finally {
      setExporting(false);
    }
  };

  const onExport = async () => {
    await exportConfiguration();
    onClose();
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
                      {t_i18n(config.group as string)}
                    </Typography>
                  )}
                  <ExportBundleInstancesAccordion
                    config={config}
                    mode={instanceModes[config.entityType] ?? 'all'}
                    selectedIds={instanceSelectedIds[config.entityType] ?? new Set<string>()}
                    onModeChange={handleInstanceModeChange(config.entityType)}
                    onToggleId={handleToggleInstanceId(config.entityType)}
                    accordionSx={accordionSx}
                  />
                </React.Fragment>
              );
            })}

            {EXPORT_CATEGORIES.map((category) => {
              if (category.kind === 'placeholder') {
                return (
                  <Accordion key={category.key} disableGutters expanded={false} sx={{ ...accordionSx, opacity: 0.5 }}>
                    <AccordionSummary sx={{ cursor: 'default' }}>
                      <FormControlLabel
                        control={<Checkbox disabled checked={false} />}
                        label={<Typography fontWeight="bold">{t_i18n(category.label)}</Typography>}
                      />
                    </AccordionSummary>
                  </Accordion>
                );
              }

              if (category.kind === 'flat') {
                const checked = checkedCategoryItems[category.key]?.includes(category.key) ?? false;
                return (
                  <Box key={category.key} sx={{ ...accordionSx, px: 2, py: 1.5 }}>
                    <FormControlLabel
                      control={<Checkbox checked={checked} onChange={handleToggleFlatCategory(category.key)} />}
                      label={<Typography fontWeight="bold">{t_i18n(category.label)}</Typography>}
                    />
                  </Box>
                );
              }

              const items = category.items ?? [];
              const checked = checkedCategoryItems[category.key] ?? [];
              const allChecked = items.length > 0 && checked.length === items.length;
              const someChecked = checked.length > 0 && checked.length < items.length;

              return (
                <Accordion key={category.key} disableGutters sx={accordionSx}>
                  <AccordionSummary expandIcon={<ExpandMoreOutlined />}>
                    <FormControlLabel
                      onClick={(e) => e.stopPropagation()}
                      control={(
                        <Checkbox
                          checked={allChecked}
                          indeterminate={someChecked}
                          onChange={handleToggleCategoryAll(category.key, items.map((item) => item.key))}
                        />
                      )}
                      label={(
                        <Typography fontWeight="bold">
                          {t_i18n(category.label)} ({checked.length}/{items.length})
                        </Typography>
                      )}
                    />
                  </AccordionSummary>
                  <AccordionDetails sx={{ display: 'flex', flexDirection: 'column', paddingLeft: 5, paddingTop: 0, marginTop: -1 }}>
                    {items.map((item) => (
                      <FormControlLabel
                        key={item.key}
                        control={(
                          <Checkbox
                            checked={checked.includes(item.key)}
                            onChange={handleToggleCategoryItem(category.key, item.key)}
                          />
                        )}
                        label={t_i18n(item.label)}
                      />
                    ))}
                  </AccordionDetails>
                </Accordion>
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

            <TextField
              label={t_i18n('Bundle name')}
              variant="standard"
              fullWidth
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
              disabled={exporting}
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

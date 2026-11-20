import { useContext, useState } from 'react';
import Card from '@common/card/Card';
import Tooltip from '@mui/material/Tooltip';
import { Stack } from '@mui/material';
import { Add as AddIcon, CloudUploadOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { useFormatter } from '../../../../../components/i18n';
import { UserContext } from '../../../../../utils/hooks/useAuth';
import { useXTMHubResourceLink } from '../../../../../utils/hooks/useXTMHubResourceLink';
import DashboardHiddenImportInput from '../../../../../components/dashboard/import-export/DashboardHiddenImportInput';
import { useSubTypeOutletContext } from '../SubTypeOutletContext';
import useCustomViewImport from './import-export/useCustomViewImport';
import CustomViewsSettingsDataTable from './CustomViewsSettingsDataTable';
import CustomViewFormDrawer from './CustomViewFormDrawer';
import ConfigPresetPartialImportDialog from '../../config_preset/import/partial/ConfigPresetPartialImportDialog';
import useConfigPresetPartialImportAccess from '../../config_preset/import/partial/useConfigPresetPartialImportAccess';

// The configuration preset type of the custom views, and the key of their configuration that holds their entity type
const CUSTOM_VIEWS_CONFIG_PRESET_TYPE = 'customViews';
const CUSTOM_VIEW_ENTITY_TYPE_KEY = 'target_entity_type';

/**
 * Custom Views settings page.
 */
const CustomViewsSettings = () => {
  const { t_i18n } = useFormatter();
  const { subType } = useSubTypeOutletContext();
  const [isDrawerOpen, setDrawerOpen] = useState(false);
  const importHelpers = useCustomViewImport({ targetEntityType: subType.id });
  // Without the partial import (not a BYPASS user, or the CONFIG_PRESET flag off), the custom view file import stays as it is
  const canImportFromBundle = useConfigPresetPartialImportAccess();
  const [importDialogOpen, setImportDialogOpen] = useState(false);
  // After the import of custom views from a configuration bundle: the list reads its views again
  const [listVersion, setListVersion] = useState(0);
  const { isXTMHubAccessible } = useContext(UserContext);
  const importFromHubUrl = useXTMHubResourceLink('/redirect/opencti_custom_views');
  return (
    <>
      <DashboardHiddenImportInput helpers={importHelpers} />
      {canImportFromBundle && (
        <ConfigPresetPartialImportDialog
          open={importDialogOpen}
          onClose={() => setImportDialogOpen(false)}
          title={t_i18n('Import a custom view')}
          type={CUSTOM_VIEWS_CONFIG_PRESET_TYPE}
          // Only the custom views of this entity type: the ones of the other types of the bundle are not offered
          scope={{ key: CUSTOM_VIEW_ENTITY_TYPE_KEY, value: subType.id }}
          itemsLabel={t_i18n('custom views')}
          fileLabel={t_i18n('Import a custom view file')}
          fileDescription={t_i18n('A custom view exported as a JSON file')}
          bundleDescription={t_i18n('Select the custom views to import from a full configuration bundle (zip)')}
          onBundleImported={() => setListVersion((version) => version + 1)}
          // The same file import as without the dialog: the dialog closes, the file picker opens, and the import tells its outcome as before
          onChooseFile={() => {
            setImportDialogOpen(false);
            importHelpers.handleImport();
          }}
        />
      )}
      <Card
        title={t_i18n('Custom Views')}
        sx={{
        // Compensate existing top padding from data table header
        //  to avoid the feeling of having too much empty space.
          pt: 2,
        }}
        action={(
          <Stack direction="row" sx={{ alignItems: 'center', gap: 1 }}>
            {isXTMHubAccessible && importFromHubUrl && (
              <Button
                gradient
                href={importFromHubUrl}
                target="_blank"
                rel="noopener noreferrer"
                title={t_i18n('Import from Hub')}
              >
                {t_i18n('Import from Hub')}
              </Button>
            )}
            <Tooltip title={t_i18n('Create a new custom view')}>
              <IconButton
                aria-label={t_i18n('Create a new custom view')}
                onClick={() => setDrawerOpen(true)}
                size="small"
              >
                <AddIcon fontSize="small" color="primary" />
              </IconButton>
            </Tooltip>
            <Tooltip title={t_i18n('Import a custom view')}>
              <IconButton
                disabled={importHelpers.importing}
                onClick={canImportFromBundle ? () => setImportDialogOpen(true) : importHelpers.handleImport}
                size="small"
                aria-label={t_i18n('Import a custom view')}
              >
                <CloudUploadOutlined fontSize="small" color="primary" />
              </IconButton>
            </Tooltip>
          </Stack>
        )}
      >
        <CustomViewsSettingsDataTable key={listVersion} targetType={subType.id} />
      </Card>
      <CustomViewFormDrawer
        isOpen={isDrawerOpen}
        entityType={subType.id}
        onClose={() => {
          setDrawerOpen(false);
        }}
      />
    </>
  );
};

export default CustomViewsSettings;

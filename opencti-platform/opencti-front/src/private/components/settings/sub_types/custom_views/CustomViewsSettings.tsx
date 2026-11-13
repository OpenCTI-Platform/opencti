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

/**
 * Custom Views settings page.
 */
const CustomViewsSettings = () => {
  const { t_i18n } = useFormatter();
  const { subType } = useSubTypeOutletContext();
  const [isDrawerOpen, setDrawerOpen] = useState(false);
  const importHelpers = useCustomViewImport({ targetEntityType: subType.id });
  const { isXTMHubAccessible } = useContext(UserContext);
  const importFromHubUrl = useXTMHubResourceLink('/redirect/opencti_custom_views');
  return (
    <>
      <DashboardHiddenImportInput helpers={importHelpers} />
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
                onClick={importHelpers.handleImport}
                size="small"
                aria-label={t_i18n('Import a custom view')}
              >
                <CloudUploadOutlined fontSize="small" color="primary" />
              </IconButton>
            </Tooltip>
          </Stack>
        )}
      >
        <CustomViewsSettingsDataTable targetType={subType.id} />
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

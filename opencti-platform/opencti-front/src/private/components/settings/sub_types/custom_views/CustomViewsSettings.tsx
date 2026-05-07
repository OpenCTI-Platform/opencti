import { useState } from 'react';
import Card from '@common/card/Card';
import Tooltip from '@mui/material/Tooltip';
import { Add as AddIcon, CloudUploadOutlined } from '@mui/icons-material';
import IconButton from '@common/button/IconButton';
import { useFormatter } from '../../../../../components/i18n';
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
          <>
            <Tooltip title={t_i18n('Create a new custom view')}>
              <IconButton
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
              >
                <CloudUploadOutlined fontSize="small" color="primary" />
              </IconButton>
            </Tooltip>
          </>
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

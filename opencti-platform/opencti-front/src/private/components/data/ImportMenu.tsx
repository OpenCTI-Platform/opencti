import React from 'react';
import NavToolbarMenu from '@components/common/menus/NavToolbarMenu';
import Tab from '@mui/material/Tab';
import { Link, useLocation } from 'react-router-dom';
import Tabs from '@mui/material/Tabs';
import useHelper from '../../../utils/hooks/useHelper';
import { useFormatter } from '../../../components/i18n';

const ImportMenu = () => {
  const { t_i18n } = useFormatter();
  const location = useLocation();
  const { isFeatureEnable } = useHelper();
  const isNewImportScreensEnabled = isFeatureEnable('NEW_IMPORT_SCREENS');
  const isDraftFeatureEnabled = isFeatureEnable('DRAFT_WORKSPACE');

  if (!isNewImportScreensEnabled) {
    return (
      <NavToolbarMenu
        entries={[{
          path: '/dashboard/data/import',
          label: 'Import',
        }]}
      />
    );
  }

  return (
    <Tabs value={location.pathname} sx={{ paddingBottom: 3 }}>
      <Tab
        component={Link}
        to={'/dashboard/data/import/file'}
        value={'/dashboard/data/import/file'}
        label={t_i18n('Global files')}
      />
      {isDraftFeatureEnabled && (
        <Tab
          component={Link}
          to={'/dashboard/data/import/draft'}
          value={'/dashboard/data/import/draft'}
          label={t_i18n('Drafts')}
        />
      )}
      <Tab
        component={Link}
        to={'/dashboard/data/import/workbench'}
        value={'/dashboard/data/import/workbench'}
        label={t_i18n('Analyst workbenches')}
      />
    </Tabs>
  );
};

export default ImportMenu;

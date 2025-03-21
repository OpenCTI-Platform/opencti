import React from 'react';
import NavToolbarMenu, { MenuEntry } from '@components/common/menus/NavToolbarMenu';
import useHelper from '../../../utils/hooks/useHelper';

const ImportMenu = () => {
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
  const entries: MenuEntry[] = [
    {
      path: '/dashboard/data/import/file',
      label: 'Uploaded files',
    },
    isDraftFeatureEnabled ? {
      path: '/dashboard/data/import/draft',
      label: 'Drafts',
    } : null,
    {
      path: '/dashboard/data/import/workbench',
      label: 'Analyst workbenches',
    },
  ].filter((entry) => entry !== null);
  return <NavToolbarMenu entries={entries} />;
};

export default ImportMenu;

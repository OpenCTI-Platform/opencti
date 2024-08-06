import React from 'react';
import NavToolbarMenu, { MenuEntry } from '@components/common/menus/NavToolbarMenu';

const ImportMenu = () => {
  const entries: MenuEntry[] = [
    {
      path: '/dashboard/data/import/file',
      label: 'Uploaded files',
    },
    {
      path: '/dashboard/data/import/workbench',
      label: 'Analyst workbenches',
    },
    {
      path: '/dashboard/data/import/connectors',
      label: 'Enabled import connectors',
    },
  ];
  return <NavToolbarMenu entries={entries} />;
};

export default ImportMenu;

import React from 'react';
import NavToolbarMenu, { MenuEntry } from '@components/common/menus/NavToolbarMenu';

const ManagementMenu = () => {
  const entries: MenuEntry[] = [
    {
      path: '/dashboard/data/management/restricted',
      label: 'Restricted entities',
    },
  ];
  return <NavToolbarMenu entries={entries} />;
};

export default ManagementMenu;

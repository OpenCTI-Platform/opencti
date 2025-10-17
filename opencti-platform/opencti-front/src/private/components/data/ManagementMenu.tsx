import React from 'react';
import NavToolbarMenu, { MenuEntry } from '@components/common/menus/NavToolbarMenu';

const ManagementMenu = () => {
  const entries: MenuEntry[] = [
    {
      path: '/dashboard/data/restriction/restricted',
      label: 'Restricted entities',
    },
    {
      path: '/dashboard/data/restriction/drafts',
      label: 'Drafts'
    }
  ];
  return <NavToolbarMenu entries={entries} />;
};

export default ManagementMenu;

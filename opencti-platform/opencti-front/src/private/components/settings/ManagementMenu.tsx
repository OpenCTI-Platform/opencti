import React, { FunctionComponent } from 'react';
import NavToolbarMenu, { MenuEntry } from '../common/menus/NavToolbarMenu';

const ManagementMenu: FunctionComponent = () => {
  const entries: MenuEntry[] = [
    {
      path: '/dashboard/settings/management/drafts',
      label: 'Drafts',
    },
  ];

  return <NavToolbarMenu entries={entries} />;
};

export default ManagementMenu;

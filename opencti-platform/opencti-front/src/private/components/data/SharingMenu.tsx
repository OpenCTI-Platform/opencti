import React from 'react';
import NavToolbarMenu, { MenuEntry } from '@components/common/menus/NavToolbarMenu';

const SharingMenu = () => {
  const entries: MenuEntry[] = [
    {
      path: '/dashboard/data/sharing/streams',
      label: 'Live streams',
    },
    {
      path: '/dashboard/data/sharing/feeds',
      label: 'CSV feeds',
    },
    {
      path: '/dashboard/data/sharing/taxii',
      label: 'TAXII collections',
    },
  ];
  return <NavToolbarMenu entries={entries} />;
};

export default SharingMenu;

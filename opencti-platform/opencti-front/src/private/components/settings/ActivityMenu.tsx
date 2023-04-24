import React, { FunctionComponent } from 'react';
import NavToolbarMenu, { MenuEntry } from '../common/menus/NavToolbarMenu';

const ActivityMenu: FunctionComponent = () => {
  const entries: MenuEntry[] = [
    {
      path: '/dashboard/settings/activity/audit',
      label: 'Audit logs',
    },
    {
      path: '/dashboard/settings/activity/configuration',
      label: 'Configuration',
    },
  ];

  return <NavToolbarMenu entries={entries} />;
};

export default ActivityMenu;

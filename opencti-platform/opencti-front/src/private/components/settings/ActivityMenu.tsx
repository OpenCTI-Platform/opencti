import React, { FunctionComponent } from 'react';
import NavToolbarMenu, { MenuEntry } from '../common/menus/NavToolbarMenu';

const ActivityMenu: FunctionComponent = () => {
  const entries: MenuEntry[] = [
    {
      path: '/dashboard/settings/activity/audit',
      label: 'Events',
    },
    {
      path: '/dashboard/settings/activity/configuration',
      label: 'Configuration',
    },
    {
      path: '/dashboard/settings/activity/alerting',
      label: 'Alerting',
    },
  ];

  return <NavToolbarMenu entries={entries} />;
};

export default ActivityMenu;

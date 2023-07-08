import React, { FunctionComponent } from 'react';
import NavToolbarMenu, { MenuEntry } from '../common/menus/NavToolbarMenu';

const NotificationMenu: FunctionComponent = () => {
  const entries: MenuEntry[] = [
    {
      path: '/dashboard/settings/notification/notifier',
      label: 'Notifiers',
    },
  ];

  return <NavToolbarMenu entries={entries} />;
};

export default NotificationMenu;

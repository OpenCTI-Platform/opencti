import React, { FunctionComponent } from 'react';
import {
  CenterFocusStrongOutlined,
  GroupOutlined,
  PermIdentityOutlined,
  ReceiptOutlined,
  Security,
} from '@mui/icons-material';
import NavToolbarMenu, { MenuEntry } from '../common/menus/NavToolbarMenu';

const SettingsMenu: FunctionComponent = () => {
  const entries: MenuEntry[] = [
    {
      path: '/dashboard/settings/accesses/roles',
      label: 'Roles',
      icon: <Security fontSize="medium" />,
    },
    {
      path: '/dashboard/settings/accesses/users',
      label: 'Users',
      icon: <PermIdentityOutlined fontSize="medium" />,
    },
    {
      path: '/dashboard/settings/accesses/groups',
      label: 'Groups',
      icon: <GroupOutlined fontSize="medium" />,
    },
    {
      path: '/dashboard/settings/accesses/marking',
      label: 'Marking definitions',
      icon: <CenterFocusStrongOutlined fontSize="medium" />,
    },
    {
      path: '/dashboard/settings/accesses/sessions',
      label: 'Sessions',
      icon: <ReceiptOutlined fontSize="medium" />,
    },
  ];

  return <NavToolbarMenu entries={entries} />;
};

export default SettingsMenu;

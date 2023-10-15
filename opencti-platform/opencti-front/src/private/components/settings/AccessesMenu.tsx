import React, { FunctionComponent } from 'react';
import {
  CenterFocusStrongOutlined,
  PermIdentityOutlined,
  ReceiptOutlined,
  LocalPoliceOutlined,
  SecurityOutlined,
  AccountBalanceOutlined,
} from '@mui/icons-material';
import { AccountGroupOutline } from 'mdi-material-ui';
import NavToolbarMenu, { MenuEntry } from '../common/menus/NavToolbarMenu';
import useGranted, {
  VIRTUAL_ORGANIZATION_ADMIN,
  SETTINGS_SETACCESSES,
  SETTINGS_SETMARKINGS,
} from '../../../utils/hooks/useGranted';

const AccessesMenu: FunctionComponent = () => {
  const entries: MenuEntry[] = [
    {
      path: '/dashboard/settings/accesses/roles',
      label: 'Roles',
      icon: <SecurityOutlined fontSize="medium" />,
    },
    {
      path: '/dashboard/settings/accesses/groups',
      label: 'Groups',
      icon: <AccountGroupOutline fontSize="medium" />,
    },
    {
      path: '/dashboard/settings/accesses/users',
      label: 'Users',
      icon: <PermIdentityOutlined fontSize="medium" />,
    },
    {
      path: '/dashboard/settings/accesses/organizations',
      label: 'Organizations',
      icon: <AccountBalanceOutlined fontSize="medium" />,
    },
    {
      path: '/dashboard/settings/accesses/sessions',
      label: 'Sessions',
      icon: <ReceiptOutlined fontSize="medium" />,
    },
    {
      path: '/dashboard/settings/accesses/policies',
      label: 'Policies',
      icon: <LocalPoliceOutlined fontSize="medium" />,
    },
  ];
  const markingEntries: MenuEntry[] = [
    {
      path: '/dashboard/settings/accesses/marking',
      label: 'Marking definitions',
      icon: <CenterFocusStrongOutlined fontSize="medium" />,
    },
  ];
  const setAccess = useGranted([SETTINGS_SETACCESSES]);
  const setMarkings = useGranted([SETTINGS_SETMARKINGS]);
  const isOrgaAdmin = useGranted([VIRTUAL_ORGANIZATION_ADMIN]);
  const menuEntries = [];
  if (setAccess) {
    menuEntries.push(...entries);
  }
  if (setMarkings) {
    menuEntries.push(...markingEntries);
  }
  if (menuEntries.length === 0 && isOrgaAdmin) {
    menuEntries.push(
      ...[
        {
          path: '/dashboard/settings/accesses/organizations',
          label: 'Organizations',
          icon: <AccountBalanceOutlined fontSize="medium" />,
        },
        {
          path: '/dashboard/settings/accesses/users',
          label: 'Users',
          icon: <PermIdentityOutlined fontSize="medium" />,
        },
      ],
    );
  }
  return <NavToolbarMenu entries={menuEntries} />;
};

export default AccessesMenu;

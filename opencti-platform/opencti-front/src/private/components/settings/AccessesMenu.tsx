import React, { FunctionComponent } from 'react';
import {
  CenterFocusStrongOutlined,
  GroupOutlined,
  PermIdentityOutlined,
  ReceiptOutlined,
  Security as SecurityIcon,
} from '@mui/icons-material';
import NavToolbarMenu, { MenuEntry } from '../common/menus/NavToolbarMenu';
import useGranted, { SETTINGS_SETACCESSES } from '../../../utils/hooks/useGranted';
import Security from '../../../utils/Security';

const SettingsMenu: FunctionComponent = () => {
  const entries: MenuEntry[] = [
    {
      path: '/dashboard/settings/accesses/roles',
      label: 'Roles',
      icon: <SecurityIcon fontSize="medium" />,
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

  const markingEntries: MenuEntry[] = [
    {
      path: '/dashboard/settings/accesses/marking',
      label: 'Marking definitions',
      icon: <CenterFocusStrongOutlined fontSize="medium" />,
    },
  ];

  const setAccess = useGranted([SETTINGS_SETACCESSES]);
  if (setAccess) {
    return (
      <Security needs={[SETTINGS_SETACCESSES]}>
        <NavToolbarMenu entries={entries} />
      </Security>
    );
  }
  return <NavToolbarMenu entries={markingEntries} />;
};

export default SettingsMenu;

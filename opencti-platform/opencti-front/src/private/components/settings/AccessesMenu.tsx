import React, { FunctionComponent } from 'react';
import {
  AccountBalanceOutlined,
  AlternateEmailOutlined,
  CenterFocusStrongOutlined,
  EmailOutlined,
  LocalPoliceOutlined,
  PermIdentityOutlined,
  ReceiptOutlined,
  SecurityOutlined,
} from '@mui/icons-material';
import { AccountGroupOutline } from 'mdi-material-ui';
import NavToolbarMenu, { MenuEntry } from '../common/menus/NavToolbarMenu';
import useGranted, { SETTINGS_SETACCESSES, SETTINGS_SETDISSEMINATION, SETTINGS_SETMARKINGS, VIRTUAL_ORGANIZATION_ADMIN } from '../../../utils/hooks/useGranted';

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
  const disseminationEntries: MenuEntry[] = [
    {
      path: '/dashboard/settings/accesses/dissemination_list',
      label: 'Dissemination list',
      icon: <AlternateEmailOutlined fontSize="medium" />,
      isEE: true,
    },
  ];
  const emailTemplateEntries: MenuEntry[] = [
    {
      path: '/dashboard/settings/accesses/email_templates',
      label: 'Email templates',
      icon: <EmailOutlined fontSize="medium" />,
      isEE: true,
    },
  ];
  const singleSignOnEntries: MenuEntry[] = [
    {
      path: '/dashboard/settings/accesse/single_sign_on',
      label: 'SSO definition',
      icon: <div />,
      isEE: true,
    }
  ]
  const setAccess = useGranted([SETTINGS_SETACCESSES]);
  const setMarkings = useGranted([SETTINGS_SETMARKINGS]);
  const isOrgaAdmin = useGranted([VIRTUAL_ORGANIZATION_ADMIN]);
  const setDissemination = useGranted([SETTINGS_SETDISSEMINATION]);
  const menuEntries = [];
  if (setAccess) {
    menuEntries.push(...entries);
  }
  if (setMarkings) {
    menuEntries.push(...markingEntries);
  }
  if (setDissemination) {
    menuEntries.push(...disseminationEntries);
  }
  if (setAccess) {
    menuEntries.push(...emailTemplateEntries);
  }
  menuEntries.push(...singleSignOnEntries);
  if (!setAccess && isOrgaAdmin) {
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

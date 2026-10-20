import React from 'react';
import {
  AccountBalanceOutlined,
  AlternateEmailOutlined,
  CenterFocusStrongOutlined,
  EmailOutlined,
  ForwardToInboxOutlined,
  KeyOutlined,
  LocalPoliceOutlined,
  PermIdentityOutlined,
  ReceiptOutlined,
  SecurityOutlined,
} from '@mui/icons-material';
import { AccountGroupOutline } from 'mdi-material-ui';
import type { MenuEntry } from '../common/menus/NavToolbarMenu';
import { SETTINGS_SETACCESSES, SETTINGS_SETAUTH, SETTINGS_SETDISSEMINATION, SETTINGS_SETMARKINGS, VIRTUAL_ORGANIZATION_ADMIN } from '../../../utils/hooks/useGranted';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
export const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/settings/accesses/users',
    label: 'Users',
    icon: <PermIdentityOutlined fontSize="medium" />,
    keywords: ['account', 'member', 'api token', 'password'],
    // Organization admins can manage users of their organization.
    requiredCapabilities: [SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN],
  },
  {
    path: '/dashboard/settings/accesses/groups',
    label: 'Groups',
    icon: <AccountGroupOutline fontSize="medium" />,
    keywords: ['permissions', 'default markings', 'default assignation'],
    requiredCapabilities: [SETTINGS_SETACCESSES],
  },
  {
    path: '/dashboard/settings/accesses/organizations',
    label: 'Organizations',
    icon: <AccountBalanceOutlined fontSize="medium" />,
    keywords: ['tenant', 'sharing', 'multi-tenancy'],
    requiredCapabilities: [SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN],
  },
  {
    path: '/dashboard/settings/accesses/roles',
    label: 'Roles',
    icon: <SecurityOutlined fontSize="medium" />,
    keywords: ['capabilities', 'rbac', 'permissions'],
    requiredCapabilities: [SETTINGS_SETACCESSES],
  },
  {
    path: '/dashboard/settings/accesses/sessions',
    label: 'Sessions',
    icon: <ReceiptOutlined fontSize="medium" />,
    keywords: ['logout', 'kill session', 'connected users'],
    requiredCapabilities: [SETTINGS_SETACCESSES],
  },
  {
    path: '/dashboard/settings/accesses/policies',
    label: 'Policies',
    icon: <LocalPoliceOutlined fontSize="medium" />,
    keywords: ['password policy', 'login', 'security policy'],
    requiredCapabilities: [SETTINGS_SETACCESSES],
  },
  {
    path: '/dashboard/settings/accesses/authentications',
    label: 'Authentications',
    icon: <KeyOutlined fontSize="medium" />,
    keywords: ['sso', 'saml', 'oidc', 'ldap', 'oauth', 'login'],
    requiredCapabilities: [SETTINGS_SETAUTH],
  },
  {
    path: '/dashboard/settings/accesses/marking',
    label: 'Marking definitions',
    icon: <CenterFocusStrongOutlined fontSize="medium" />,
    keywords: ['tlp', 'pap', 'classification', 'confidentiality', 'statement'],
    requiredCapabilities: [SETTINGS_SETMARKINGS],
  },
  {
    path: '/dashboard/settings/accesses/dissemination_list',
    label: 'Dissemination list',
    icon: <AlternateEmailOutlined fontSize="medium" />,
    keywords: ['mailing list', 'email', 'send report'],
    requiredCapabilities: [SETTINGS_SETDISSEMINATION],
    isEE: true,
  },
  {
    path: '/dashboard/settings/accesses/email_templates',
    label: 'Email templates',
    icon: <EmailOutlined fontSize="medium" />,
    keywords: ['notification', 'message'],
    requiredCapabilities: [SETTINGS_SETACCESSES],
    isEE: true,
  },
  {
    path: '/dashboard/settings/accesses/smtp',
    label: 'SMTP configuration',
    icon: <ForwardToInboxOutlined fontSize="medium" />,
    keywords: ['mail server', 'email'],
    requiredCapabilities: [SETTINGS_SETACCESSES],
  },
];

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
import type { MenuEntry } from '../common/menus/menuEntry';
import { SETTINGS_SETACCESSES, SETTINGS_SETAUTH, SETTINGS_SETDISSEMINATION, SETTINGS_SETMARKINGS, VIRTUAL_ORGANIZATION_ADMIN } from '../../../utils/hooks/capabilities';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/settings/accesses/users',
    label: 'Users',
    icon: <PermIdentityOutlined fontSize="medium" />,
    keywords: ['people', 'invite', 'Service', 'account', 'Member', 'token', 'Password'],
    // Organization admins can manage users of their organization.
    requiredCapabilities: [SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN],
  },
  {
    path: '/dashboard/settings/accesses/groups',
    label: 'Groups',
    icon: <AccountGroupOutline fontSize="medium" />,
    keywords: ['team', 'Permissions', 'default', 'Marking'],
    requiredCapabilities: [SETTINGS_SETACCESSES],
  },
  {
    path: '/dashboard/settings/accesses/organizations',
    label: 'Organizations',
    icon: <AccountBalanceOutlined fontSize="medium" />,
    keywords: ['company', 'segregation', 'subsidiaries', 'tenant'],
    requiredCapabilities: [SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN],
  },
  {
    path: '/dashboard/settings/accesses/roles',
    label: 'Roles',
    icon: <SecurityOutlined fontSize="medium" />,
    keywords: ['Capabilities', 'rbac', 'Permissions', 'privileges', 'authorization'],
    requiredCapabilities: [SETTINGS_SETACCESSES],
  },
  {
    path: '/dashboard/settings/accesses/sessions',
    label: 'Sessions',
    icon: <ReceiptOutlined fontSize="medium" />,
    keywords: ['Logout', 'Kill', 'online', 'Connected'],
    requiredCapabilities: [SETTINGS_SETACCESSES],
  },
  {
    path: '/dashboard/settings/accesses/policies',
    label: 'Policies',
    icon: <LocalPoliceOutlined fontSize="medium" />,
    keywords: ['policy', 'Password', 'Login', 'Banner', 'consent', 'timeout'],
    requiredCapabilities: [SETTINGS_SETACCESSES],
  },
  {
    path: '/dashboard/settings/accesses/authentications',
    label: 'Authentications',
    icon: <KeyOutlined fontSize="medium" />,
    keywords: ['SSO', 'saml', 'oidc', 'ldap', 'oauth', 'Login', 'idp', 'okta', 'entra', 'mfa', 'Directory'],
    requiredCapabilities: [SETTINGS_SETAUTH],
  },
  {
    path: '/dashboard/settings/accesses/marking',
    label: 'Marking definitions',
    icon: <CenterFocusStrongOutlined fontSize="medium" />,
    keywords: ['tlp', 'pap', 'classification', 'confidentiality', 'sensitivity'],
    requiredCapabilities: [SETTINGS_SETMARKINGS],
  },
  {
    path: '/dashboard/settings/accesses/dissemination_list',
    label: 'Dissemination list',
    icon: <AlternateEmailOutlined fontSize="medium" />,
    keywords: ['Distribution', 'Recipients', 'Email', 'mailing'],
    requiredCapabilities: [SETTINGS_SETDISSEMINATION],
    isEE: true,
  },
  {
    path: '/dashboard/settings/accesses/email_templates',
    label: 'Email templates',
    icon: <EmailOutlined fontSize="medium" />,
    keywords: ['HTML', 'Layout', 'Notification'],
    requiredCapabilities: [SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN],
    isEE: true,
  },
  {
    path: '/dashboard/settings/accesses/smtp',
    label: 'SMTP configuration',
    icon: <ForwardToInboxOutlined fontSize="medium" />,
    keywords: ['mail', 'Email', 'relay', 'Server'],
    requiredCapabilities: [SETTINGS_SETACCESSES],
  },
];

export default menuEntries;

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
    keywords: ['people', 'create user', 'invite', 'Service account', 'analyst', 'Member', 'api token', 'Password'],
    // Organization admins can manage users of their organization.
    requiredCapabilities: [SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN],
  },
  {
    path: '/dashboard/settings/accesses/groups',
    label: 'Groups',
    icon: <AccountGroupOutline fontSize="medium" />,
    keywords: ['team', 'user group', 'access group', 'max marking', 'Permissions', 'Default markings', 'default assignation'],
    requiredCapabilities: [SETTINGS_SETACCESSES],
  },
  {
    path: '/dashboard/settings/accesses/organizations',
    label: 'Organizations',
    icon: <AccountBalanceOutlined fontSize="medium" />,
    keywords: ['company', 'segregation', 'Platform organization', 'subsidiaries', 'tenant', 'Sharing', 'multi-tenancy'],
    requiredCapabilities: [SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN],
  },
  {
    path: '/dashboard/settings/accesses/roles',
    label: 'Roles',
    icon: <SecurityOutlined fontSize="medium" />,
    keywords: ['access rights', 'privileges', 'authorization', 'admin rights', 'Capabilities', 'rbac', 'Permissions'],
    requiredCapabilities: [SETTINGS_SETACCESSES],
  },
  {
    path: '/dashboard/settings/accesses/sessions',
    label: 'Sessions',
    icon: <ReceiptOutlined fontSize="medium" />,
    keywords: ['active sessions', 'online users', 'who is connected', 'Logout', 'kill session'],
    requiredCapabilities: [SETTINGS_SETACCESSES],
  },
  {
    path: '/dashboard/settings/accesses/policies',
    label: 'Policies',
    icon: <LocalPoliceOutlined fontSize="medium" />,
    keywords: ['platform policy', 'login banner', 'consent', 'terms', 'session timeout', 'password policy', 'security policy'],
    requiredCapabilities: [SETTINGS_SETACCESSES],
  },
  {
    path: '/dashboard/settings/accesses/authentications',
    label: 'Authentications',
    icon: <KeyOutlined fontSize="medium" />,
    keywords: ['identity provider', 'idp', 'active directory', 'entra', 'okta', 'mfa', 'SSO', 'saml', 'oidc', 'ldap', 'oauth', 'Login'],
    requiredCapabilities: [SETTINGS_SETAUTH],
  },
  {
    path: '/dashboard/settings/accesses/marking',
    label: 'Marking definitions',
    icon: <CenterFocusStrongOutlined fontSize="medium" />,
    keywords: ['tlp:red', 'tlp:amber', 'tlp:clear', 'sensitivity', 'handling', 'sharing level', 'pap', 'classification', 'confidentiality'],
    requiredCapabilities: [SETTINGS_SETMARKINGS],
  },
  {
    path: '/dashboard/settings/accesses/dissemination_list',
    label: 'Dissemination list',
    icon: <AlternateEmailOutlined fontSize="medium" />,
    keywords: ['distribution list', 'Recipients', 'share by email', 'diffusion', 'mailing list', 'send report'],
    requiredCapabilities: [SETTINGS_SETDISSEMINATION],
    isEE: true,
  },
  {
    path: '/dashboard/settings/accesses/email_templates',
    label: 'Email templates',
    icon: <EmailOutlined fontSize="medium" />,
    keywords: ['html email', 'email layout', 'Notification'],
    requiredCapabilities: [SETTINGS_SETACCESSES],
    isEE: true,
  },
  {
    path: '/dashboard/settings/accesses/smtp',
    label: 'SMTP configuration',
    icon: <ForwardToInboxOutlined fontSize="medium" />,
    keywords: ['mail relay', 'outgoing mail', 'email settings', 'mail server'],
    requiredCapabilities: [SETTINGS_SETACCESSES],
  },
];

export default menuEntries;

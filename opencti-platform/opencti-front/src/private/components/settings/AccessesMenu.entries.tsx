import { Icon } from '@filigran/design-system';
import type { MenuEntry } from '../common/menus/menuEntry';
import { SETTINGS_SETACCESSES, SETTINGS_SETAUTH, SETTINGS_SETDISSEMINATION, SETTINGS_SETMARKINGS, VIRTUAL_ORGANIZATION_ADMIN } from '../../../utils/hooks/capabilities';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/settings/accesses/users',
    label: 'Users',
    icon: <Icon name="user" size={16} />,
    keywords: ['people', 'invite', 'Service', 'account', 'Member', 'token', 'Password'],
    // Organization admins can manage users of their organization.
    requiredCapabilities: [SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN],
  },
  {
    path: '/dashboard/settings/accesses/groups',
    label: 'Groups',
    icon: <Icon name="users" size={16} />,
    keywords: ['team', 'Permissions', 'default', 'Marking'],
    requiredCapabilities: [SETTINGS_SETACCESSES],
  },
  {
    path: '/dashboard/settings/accesses/organizations',
    label: 'Organizations',
    icon: <Icon name="building-2" size={16} />,
    keywords: ['company', 'segregation', 'subsidiaries', 'tenant'],
    requiredCapabilities: [SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN],
  },
  {
    path: '/dashboard/settings/accesses/roles',
    label: 'Roles',
    icon: <Icon name="shield" size={16} />,
    keywords: ['Capabilities', 'rbac', 'Permissions', 'privileges', 'authorization'],
    requiredCapabilities: [SETTINGS_SETACCESSES],
  },
  {
    path: '/dashboard/settings/accesses/sessions',
    label: 'Sessions',
    icon: <Icon name="monitor-smartphone" size={16} />,
    keywords: ['Logout', 'Kill', 'online', 'Connected'],
    requiredCapabilities: [SETTINGS_SETACCESSES],
  },
  {
    path: '/dashboard/settings/accesses/policies',
    label: 'Policies',
    icon: <Icon name="lock" size={16} />,
    keywords: ['policy', 'Password', 'Login', 'Banner', 'consent', 'timeout'],
    requiredCapabilities: [SETTINGS_SETACCESSES],
  },
  {
    path: '/dashboard/settings/accesses/authentications',
    label: 'Authentications',
    icon: <Icon name="key-round" size={16} />,
    keywords: ['SSO', 'saml', 'oidc', 'ldap', 'oauth', 'Login', 'idp', 'okta', 'entra', 'mfa', 'Directory'],
    requiredCapabilities: [SETTINGS_SETAUTH],
  },
  {
    path: '/dashboard/settings/accesses/marking',
    label: 'Marking definitions',
    icon: <Icon name="focus" size={16} />,
    keywords: ['tlp', 'pap', 'classification', 'confidentiality', 'sensitivity'],
    requiredCapabilities: [SETTINGS_SETMARKINGS],
  },
  {
    path: '/dashboard/settings/accesses/dissemination_list',
    label: 'Dissemination list',
    icon: <Icon name="send" size={16} />,
    keywords: ['Distribution', 'Recipients', 'Email', 'mailing'],
    requiredCapabilities: [SETTINGS_SETDISSEMINATION],
    isEE: true,
  },
  {
    path: '/dashboard/settings/accesses/email_templates',
    label: 'Email templates',
    icon: <Icon name="mail" size={16} />,
    keywords: ['HTML', 'Layout', 'Notification'],
    requiredCapabilities: [SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN],
    isEE: true,
  },
  {
    path: '/dashboard/settings/accesses/smtp',
    label: 'SMTP configuration',
    icon: <Icon name="inbox" size={16} />,
    keywords: ['mail', 'Email', 'relay', 'Server'],
    requiredCapabilities: [SETTINGS_SETACCESSES],
  },
];

export default menuEntries;

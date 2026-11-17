import type { MenuEntry } from '../common/menus/menuEntry';
import { SETTINGS_SECURITYACTIVITY } from '../../../utils/hooks/capabilities';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/settings/activity/audit',
    label: 'Events',
    keywords: ['audit trail', 'user activity', 'access log', 'who did what', 'Logs', 'History'],
    requiredCapabilities: [SETTINGS_SECURITYACTIVITY],
  },
  {
    path: '/dashboard/settings/activity/configuration',
    label: 'Configuration',
    keywords: ['audit configuration', 'activity tracking', 'logging settings', 'listened users', 'Logs', 'Retention'],
    requiredCapabilities: [SETTINGS_SECURITYACTIVITY],
  },
  {
    path: '/dashboard/settings/activity/alerting',
    label: 'Alerting',
    keywords: ['audit alert', 'security alert', 'suspicious activity', 'Notification', 'Trigger'],
    requiredCapabilities: [SETTINGS_SECURITYACTIVITY],
  },
];

export default menuEntries;

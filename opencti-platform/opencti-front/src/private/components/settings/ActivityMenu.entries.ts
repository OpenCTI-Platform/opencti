import type { MenuEntry } from '../common/menus/menuEntry';
import { SETTINGS_SECURITYACTIVITY } from '../../../utils/hooks/capabilities';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/settings/activity/audit',
    label: 'Events',
    keywords: ['audit', 'trail', 'Logs', 'History'],
    requiredCapabilities: [SETTINGS_SECURITYACTIVITY],
  },
  {
    path: '/dashboard/settings/activity/configuration',
    label: 'Configuration',
    keywords: ['audit', 'tracking', 'Logs', 'Retention'],
    requiredCapabilities: [SETTINGS_SECURITYACTIVITY],
  },
  {
    path: '/dashboard/settings/activity/alerting',
    label: 'Alerting',
    keywords: ['audit', 'suspicious', 'Notification', 'Trigger'],
    requiredCapabilities: [SETTINGS_SECURITYACTIVITY],
  },
];

export default menuEntries;

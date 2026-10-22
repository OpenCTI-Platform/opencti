import type { MenuEntry } from '../common/menus/NavToolbarMenu';
import { SETTINGS_SECURITYACTIVITY } from '../../../utils/hooks/capabilities';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
export const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/settings/activity/audit',
    label: 'Events',
    keywords: ['audit', 'logs', 'history', 'activity'],
    requiredCapabilities: [SETTINGS_SECURITYACTIVITY],
  },
  {
    path: '/dashboard/settings/activity/configuration',
    label: 'Configuration',
    keywords: ['audit', 'logs', 'activity', 'retention'],
    requiredCapabilities: [SETTINGS_SECURITYACTIVITY],
  },
  {
    path: '/dashboard/settings/activity/alerting',
    label: 'Alerting',
    keywords: ['alert', 'notification', 'trigger', 'audit'],
    requiredCapabilities: [SETTINGS_SECURITYACTIVITY],
  },
];

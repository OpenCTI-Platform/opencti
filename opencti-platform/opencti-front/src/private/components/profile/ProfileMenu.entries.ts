import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
// These pages are reached from the top bar icons, not the left bar: hence `standaloneParents`.
// Exported one by one because the top bar reads its own path and capability from them.
export const profileEntry: MenuEntry = {
  path: '/dashboard/profile/me',
  label: 'Profile',
  standaloneParents: [],
  keywords: ['my account', 'preferences', 'mfa', 'API key', 'dark mode', 'timezone', 'Password', 'api token', 'two factor', '2FA', 'Language', 'theme'],
  availableInDraft: true,
};

export const notificationCenterEntry: MenuEntry = {
  path: '/dashboard/profile/notifications',
  label: 'Notification Center',
  standaloneParents: [],
  keywords: ['inbox', 'Messages', 'my alerts', 'Notifications', 'unread', 'bell'],
  requiredCapabilities: [KNOWLEDGE],
};

const menuEntries: MenuEntry[] = [
  profileEntry,
  notificationCenterEntry,
  {
    path: '/dashboard/profile/notifications/triggers',
    label: 'Triggers',
    standaloneParents: [notificationCenterEntry.label],
    keywords: ['alert rule', 'watchlist', 'follow', 'Monitoring', 'Subscribe', 'notify me', 'digest', 'Notifier', 'subscription'],
    requiredCapabilities: [KNOWLEDGE],
  },
];

export default menuEntries;

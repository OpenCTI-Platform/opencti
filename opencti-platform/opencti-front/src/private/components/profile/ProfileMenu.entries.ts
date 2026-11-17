import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
// These pages are reached from the top bar icons, not the left bar: hence `standaloneParents`.
// Exported one by one because the top bar reads its own path and capability from them.
export const profileEntry: MenuEntry = {
  path: '/dashboard/profile/me',
  label: 'Profile',
  standaloneParents: [],
  keywords: ['account', 'preferences', 'mfa', '2FA', 'Password', 'Language', 'theme', 'timezone', 'token', 'api', 'Key'],
  availableInDraft: true,
};

export const notificationCenterEntry: MenuEntry = {
  path: '/dashboard/profile/notifications',
  label: 'Notification Center',
  standaloneParents: [],
  keywords: ['inbox', 'Messages', 'alert', 'unread'],
  requiredCapabilities: [KNOWLEDGE],
};

const menuEntries: MenuEntry[] = [
  profileEntry,
  notificationCenterEntry,
  {
    path: '/dashboard/profile/notifications/triggers',
    label: 'Triggers',
    standaloneParents: [notificationCenterEntry.label],
    keywords: ['alert', 'watchlist', 'follow', 'Monitoring', 'Subscribe', 'digest', 'Notifier'],
    requiredCapabilities: [KNOWLEDGE],
  },
];

export default menuEntries;

import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
// These pages are reached from the top bar icons, not the left bar: hence `standaloneParents`.
// Exported one by one because the top bar reads its own path and capability from them.
export const profileEntry: MenuEntry = {
  path: '/dashboard/profile/me',
  label: 'Profile',
  standaloneParents: [],
  keywords: ['account', 'user', 'me', 'password', 'api token', 'two factor', '2fa', 'language', 'theme'],
  availableInDraft: true,
};

export const notificationCenterEntry: MenuEntry = {
  path: '/dashboard/profile/notifications',
  label: 'Notification Center',
  standaloneParents: [],
  keywords: ['alerts', 'notifications', 'unread', 'bell'],
  requiredCapabilities: [KNOWLEDGE],
};

export const menuEntries: MenuEntry[] = [
  profileEntry,
  notificationCenterEntry,
  {
    path: '/dashboard/profile/notifications/triggers',
    label: 'Triggers',
    standaloneParents: [notificationCenterEntry.label],
    keywords: ['trigger', 'digest', 'live', 'notifier', 'subscription'],
    requiredCapabilities: [KNOWLEDGE],
  },
];

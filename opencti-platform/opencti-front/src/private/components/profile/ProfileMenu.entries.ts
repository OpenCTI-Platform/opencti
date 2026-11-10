import type { MenuEntry } from '../common/menus/NavToolbarMenu';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
// These pages are reached from the top bar icons, not the left bar: hence `standaloneParents`.
export const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/profile/me',
    label: 'Profile',
    standaloneParents: [],
    keywords: ['account', 'user', 'me', 'password', 'api token', 'two factor', '2fa', 'language', 'theme'],
  },
  {
    // Same rule as the top bar notification icon.
    path: '/dashboard/profile/notifications',
    label: 'Notification Center',
    standaloneParents: [],
    keywords: ['alerts', 'notifications', 'unread', 'bell'],
    requiredCapabilities: [KNOWLEDGE],
  },
  {
    path: '/dashboard/profile/notifications/triggers',
    label: 'Triggers',
    standaloneParents: ['Notification Center'],
    keywords: ['trigger', 'digest', 'live', 'notifier', 'subscription'],
    requiredCapabilities: [KNOWLEDGE],
  },
];

import type { MenuEntry } from '../../common/menus/NavToolbarMenu';
import { BYPASS } from '../../../../utils/hooks/capabilities';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
export const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/data/restriction/restricted',
    label: 'Restricted entities',
    keywords: ['restriction', 'access', 'authorized members', 'permissions'],
    requiredCapabilities: [BYPASS],
    // The route is only mounted with a valid Enterprise Edition licence (restriction/Root.tsx).
    requiresEE: true,
  },
  {
    path: '/dashboard/data/restriction/drafts',
    label: 'Restricted drafts',
    keywords: ['restriction', 'draft', 'access', 'authorized members', 'permissions'],
    requiredCapabilities: [BYPASS],
  },
];

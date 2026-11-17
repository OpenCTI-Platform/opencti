import type { MenuEntry } from '../../common/menus/menuEntry';
import { BYPASS } from '../../../../utils/hooks/capabilities';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/data/restriction/restricted',
    label: 'Restricted entities',
    keywords: ['private', 'rights', 'need to know', 'confidential', 'sharing restriction', 'access', 'Permissions', 'Authorized members'],
    requiredCapabilities: [BYPASS],
    // The route is only mounted with a valid Enterprise Edition licence (restriction/Root.tsx).
    requiresEE: true,
  },
  {
    path: '/dashboard/data/restriction/drafts',
    label: 'Restricted drafts',
    keywords: ['private draft', 'rights', 'need to know', 'confidential', 'sharing restriction', 'access', 'Permissions', 'Authorized members'],
    requiredCapabilities: [BYPASS],
  },
];

export default menuEntries;

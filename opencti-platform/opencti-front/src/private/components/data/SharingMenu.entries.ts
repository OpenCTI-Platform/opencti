import type { MenuEntry } from '../common/menus/NavToolbarMenu';
import { TAXIIAPI } from '../../../utils/hooks/capabilities';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
export const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/data/sharing/streams',
    label: 'Live streams',
    keywords: ['stream', 'sse', 'export', 'share', 'feed'],
    requiredCapabilities: [TAXIIAPI],
  },
  {
    path: '/dashboard/data/sharing/feeds',
    label: 'CSV feeds',
    keywords: ['csv', 'export', 'share', 'feed'],
    requiredCapabilities: [TAXIIAPI],
  },
  {
    path: '/dashboard/data/sharing/taxii',
    label: 'TAXII collections',
    keywords: ['taxii', 'collection', 'export', 'share'],
    requiredCapabilities: [TAXIIAPI],
  },
];

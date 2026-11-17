import type { MenuEntry } from '../common/menus/menuEntry';
import { TAXIIAPI } from '../../../utils/hooks/capabilities';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/data/sharing/streams',
    label: 'Live streams',
    keywords: ['real-time', 'push', 'Synchronization', 'siem integration', 'outgoing feed', 'Export', 'Share', 'sse'],
    requiredCapabilities: [TAXIIAPI],
  },
  {
    path: '/dashboard/data/sharing/feeds',
    label: 'CSV feeds',
    keywords: ['blocklist', 'ioc feed', 'outgoing feed', 'http feed', 'firewall feed', 'edl', 'external dynamic list', 'risk list', 'Export', 'Share'],
    requiredCapabilities: [TAXIIAPI],
  },
  {
    path: '/dashboard/data/sharing/taxii',
    label: 'TAXII collections',
    keywords: ['TAXII 2.1', 'stix', 'api', 'Publish', 'outgoing feed', 'feed server', 'Export', 'Share'],
    requiredCapabilities: [TAXIIAPI],
  },
];

export default menuEntries;

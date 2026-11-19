import type { MenuEntry } from '../common/menus/menuEntry';
import { TAXIIAPI } from '../../../utils/hooks/capabilities';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/data/sharing/streams',
    label: 'Live streams',
    keywords: ['realtime', 'push', 'Synchronization', 'SIEM', 'outgoing', 'Export', 'sse', 'feed'],
    requiredCapabilities: [TAXIIAPI],
  },
  {
    path: '/dashboard/data/sharing/feeds',
    label: 'CSV feeds',
    keywords: ['blocklist', 'iocs', 'outgoing', 'Firewall', 'edl', 'Export'],
    requiredCapabilities: [TAXIIAPI],
  },
  {
    path: '/dashboard/data/sharing/taxii',
    label: 'TAXII collections',
    keywords: ['stix', 'api', 'Publish', 'outgoing', 'feed', 'Export'],
    requiredCapabilities: [TAXIIAPI],
  },
];

export default menuEntries;

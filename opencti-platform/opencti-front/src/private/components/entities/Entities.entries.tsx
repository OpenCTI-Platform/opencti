import { Icon } from '@filigran/design-system';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/entities/sectors',
    label: 'Sectors',
    entityType: 'Sector',
    icon: <Icon name="network" size={16} />,
    keywords: ['industry', 'vertical', 'Victimology', 'naics', 'entity'],
    ...knowledge,
  },
  {
    path: '/dashboard/entities/events',
    label: 'Events',
    entityType: 'Event',
    icon: <Icon name="calendar" size={16} />,
    keywords: ['conference', 'election', 'summit', 'geopolitical', 'news', 'entity'],
    ...knowledge,
  },
  {
    path: '/dashboard/entities/organizations',
    label: 'Organizations',
    entityType: 'Organization',
    icon: <Icon name="building-2" size={16} />,
    keywords: ['company', 'Vendor', 'Identity', 'Victimology', 'entity'],
    ...knowledge,
  },
  {
    path: '/dashboard/entities/security_platforms',
    label: 'Security platforms',
    entityType: 'SecurityPlatform',
    icon: <Icon name="custom/security-platforms" size={16} />,
    keywords: ['EDR', 'XDR', 'SIEM', 'Firewall', 'Product', 'entity'],
    ...knowledge,
  },
  {
    path: '/dashboard/entities/systems',
    label: 'Systems',
    entityType: 'System',
    icon: <Icon name="server" size={16} />,
    keywords: ['asset', 'Host', 'Server', 'Endpoint', 'entity'],
    ...knowledge,
  },
  {
    path: '/dashboard/entities/individuals',
    label: 'Individuals',
    entityType: 'Individual',
    icon: <Icon name="user" size={16} />,
    keywords: ['person', 'people', 'Identity', 'Victimology', 'vip', 'entity'],
    ...knowledge,
  },
];

export default menuEntries;

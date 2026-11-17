import { AccountBalanceOutlined, DomainOutlined, EventOutlined, PersonOutlined, SecurityOutlined, StorageOutlined } from '@mui/icons-material';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/entities/sectors',
    label: 'Sectors',
    entityType: 'Sector',
    icon: <DomainOutlined fontSize="small" />,
    keywords: ['industry', 'vertical', 'Victimology', 'naics', 'entity'],
    ...knowledge,
  },
  {
    path: '/dashboard/entities/events',
    label: 'Events',
    entityType: 'Event',
    icon: <EventOutlined fontSize="small" />,
    keywords: ['conference', 'election', 'summit', 'geopolitical', 'news', 'entity'],
    ...knowledge,
  },
  {
    path: '/dashboard/entities/organizations',
    label: 'Organizations',
    entityType: 'Organization',
    icon: <AccountBalanceOutlined fontSize="small" />,
    keywords: ['company', 'Vendor', 'Identity', 'Victimology', 'entity'],
    ...knowledge,
  },
  {
    path: '/dashboard/entities/security_platforms',
    label: 'Security platforms',
    entityType: 'SecurityPlatform',
    icon: <SecurityOutlined fontSize="small" />,
    keywords: ['EDR', 'XDR', 'SIEM', 'Firewall', 'Product', 'entity'],
    ...knowledge,
  },
  {
    path: '/dashboard/entities/systems',
    label: 'Systems',
    entityType: 'System',
    icon: <StorageOutlined fontSize="small" />,
    keywords: ['asset', 'Host', 'Server', 'Endpoint', 'entity'],
    ...knowledge,
  },
  {
    path: '/dashboard/entities/individuals',
    label: 'Individuals',
    entityType: 'Individual',
    icon: <PersonOutlined fontSize="small" />,
    keywords: ['person', 'people', 'Identity', 'Victimology', 'vip', 'entity'],
    ...knowledge,
  },
];

export default menuEntries;

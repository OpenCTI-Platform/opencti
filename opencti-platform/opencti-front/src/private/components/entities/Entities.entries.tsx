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
    keywords: ['vertical', 'Victimology', 'targeted industry', 'naics'],
    ...knowledge,
  },
  {
    path: '/dashboard/entities/events',
    label: 'Events',
    entityType: 'Event',
    icon: <EventOutlined fontSize="small" />,
    keywords: ['real-world event', 'conference', 'election', 'summit', 'geopolitical event', 'crisis', 'news'],
    ...knowledge,
  },
  {
    path: '/dashboard/entities/organizations',
    label: 'Organizations',
    entityType: 'Organization',
    icon: <AccountBalanceOutlined fontSize="small" />,
    keywords: ['company', 'Enterprise', 'Target', 'Vendor', 'Identity', 'Victimology'],
    ...knowledge,
  },
  {
    path: '/dashboard/entities/security_platforms',
    label: 'Security platforms',
    entityType: 'SecurityPlatform',
    icon: <SecurityOutlined fontSize="small" />,
    keywords: ['security product', 'EDR', 'XDR', 'SIEM', 'Firewall', 'detection platform', 'security stack'],
    ...knowledge,
  },
  {
    path: '/dashboard/entities/systems',
    label: 'Systems',
    entityType: 'System',
    icon: <StorageOutlined fontSize="small" />,
    keywords: ['Host', 'Server', 'Endpoint', 'it asset', 'attack surface'],
    ...knowledge,
  },
  {
    path: '/dashboard/entities/individuals',
    label: 'Individuals',
    entityType: 'Individual',
    icon: <PersonOutlined fontSize="small" />,
    keywords: ['person', 'people', 'Identity', 'victim', 'employee', 'vip', 'contact'],
    ...knowledge,
  },
];

export default menuEntries;

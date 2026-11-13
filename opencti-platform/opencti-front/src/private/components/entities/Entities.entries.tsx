import { AccountBalanceOutlined, DomainOutlined, EventOutlined, PersonOutlined, SecurityOutlined, StorageOutlined } from '@mui/icons-material';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  { path: '/dashboard/entities/sectors', label: 'Sectors', icon: <DomainOutlined fontSize="small" />, ...knowledge },
  { path: '/dashboard/entities/events', label: 'Events', icon: <EventOutlined fontSize="small" />, ...knowledge },
  { path: '/dashboard/entities/organizations', label: 'Organizations', icon: <AccountBalanceOutlined fontSize="small" />, ...knowledge },
  { path: '/dashboard/entities/security_platforms', label: 'Security platforms', icon: <SecurityOutlined fontSize="small" />, ...knowledge },
  { path: '/dashboard/entities/systems', label: 'Systems', icon: <StorageOutlined fontSize="small" />, ...knowledge },
  { path: '/dashboard/entities/individuals', label: 'Individuals', icon: <PersonOutlined fontSize="small" />, ...knowledge },
];

export default menuEntries;

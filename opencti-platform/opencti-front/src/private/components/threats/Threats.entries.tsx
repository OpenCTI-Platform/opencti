import { DiamondOutlined } from '@mui/icons-material';
import { AccountMultipleOutline, ChessKnight, LaptopAccount } from 'mdi-material-ui';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  { path: '/dashboard/threats/threat_actors_group', label: 'Threat actors (group)', icon: <AccountMultipleOutline fontSize="small" />, ...knowledge },
  { path: '/dashboard/threats/threat_actors_individual', label: 'Threat actors (individual)', icon: <LaptopAccount fontSize="small" />, ...knowledge },
  { path: '/dashboard/threats/intrusion_sets', label: 'Intrusion sets', icon: <DiamondOutlined fontSize="small" />, ...knowledge },
  { path: '/dashboard/threats/campaigns', label: 'Campaigns', icon: <ChessKnight fontSize="small" />, ...knowledge },
];

export default menuEntries;

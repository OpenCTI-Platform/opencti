import { DiamondOutlined } from '@mui/icons-material';
import { AccountMultipleOutline, ChessKnight, LaptopAccount } from 'mdi-material-ui';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/threats/threat_actors_group',
    label: 'Threat actors (group)',
    entityType: 'Threat-Actor-Group',
    icon: <AccountMultipleOutline fontSize="small" />,
    keywords: ['apt', 'Adversary', 'gang', 'cybercriminal', 'nation', 'State', 'hacktivist', 'ransomware'],
    ...knowledge,
  },
  {
    path: '/dashboard/threats/threat_actors_individual',
    label: 'Threat actors (individual)',
    entityType: 'Threat-Actor-Individual',
    icon: <LaptopAccount fontSize="small" />,
    keywords: ['hacker', 'persona', 'insider', 'cybercriminal', 'Alias'],
    ...knowledge,
  },
  {
    path: '/dashboard/threats/intrusion_sets',
    label: 'Intrusion sets',
    entityType: 'Intrusion-Set',
    icon: <DiamondOutlined fontSize="small" />,
    keywords: ['apt', 'Adversary', 'actor', 'Cluster', 'unc'],
    ...knowledge,
  },
  {
    path: '/dashboard/threats/campaigns',
    label: 'Campaigns',
    entityType: 'Campaign',
    icon: <ChessKnight fontSize="small" />,
    keywords: ['Operation', 'wave', 'Cluster'],
    ...knowledge,
  },
];

export default menuEntries;

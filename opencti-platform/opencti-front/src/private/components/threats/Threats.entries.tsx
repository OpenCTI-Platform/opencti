import { Icon } from '@filigran/design-system';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/threats/threat_actors_group',
    label: 'Threat actors (group)',
    entityType: 'Threat-Actor-Group',
    icon: <Icon name="users" size={16} />,
    keywords: ['apt', 'Adversary', 'gang', 'cybercriminal', 'nation', 'State', 'hacktivist', 'ransomware'],
    ...knowledge,
  },
  {
    path: '/dashboard/threats/threat_actors_individual',
    label: 'Threat actors (individual)',
    entityType: 'Threat-Actor-Individual',
    icon: <Icon name="custom/threat-actor-individual" size={16} />,
    keywords: ['hacker', 'persona', 'insider', 'cybercriminal', 'Alias'],
    ...knowledge,
  },
  {
    path: '/dashboard/threats/intrusion_sets',
    label: 'Intrusion sets',
    entityType: 'Intrusion-Set',
    icon: <Icon name="custom/intrusion-set" size={16} />,
    keywords: ['apt', 'Adversary', 'actor', 'Cluster', 'unc'],
    ...knowledge,
  },
  {
    path: '/dashboard/threats/campaigns',
    label: 'Campaigns',
    entityType: 'Campaign',
    icon: <Icon name="chess-knight" size={16} />,
    keywords: ['Operation', 'wave', 'Cluster'],
    ...knowledge,
  },
];

export default menuEntries;

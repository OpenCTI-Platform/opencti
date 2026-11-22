import { Icon } from '@filigran/design-system';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/events/incidents',
    label: 'Incidents',
    entityType: 'Incident',
    icon: <Icon name="custom/fire" size={16} />,
    keywords: ['breach', 'compromise', 'intrusion', 'alert', 'attack'],
    ...knowledge,
  },
  {
    path: '/dashboard/events/sightings',
    label: 'Sightings',
    entityType: 'stix-sighting-relationship',
    icon: <Icon name="eye" size={16} />,
    keywords: ['seen', 'Detection', 'Match', 'positive', 'False'],
    ...knowledge,
  },
  {
    path: '/dashboard/events/observed_data',
    label: 'Observed datas',
    entityType: 'Observed-Data',
    icon: <Icon name="satellite-dish" size={16} />,
    keywords: ['telemetry', 'observation', 'Logs', 'evidence'],
    ...knowledge,
  },
];

export default menuEntries;

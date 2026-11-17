import { VisibilityOutlined, WifiTetheringOutlined } from '@mui/icons-material';
import { Fire } from 'mdi-material-ui';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/events/incidents',
    label: 'Incidents',
    icon: <Fire fontSize="small" />,
    keywords: ['breach', 'compromise', 'intrusion', 'security event', 'alert', 'cyber attack'],
    ...knowledge,
  },
  {
    path: '/dashboard/events/sightings',
    label: 'Sightings',
    icon: <VisibilityOutlined fontSize="small" />,
    keywords: ['seen', 'Detection', 'Match', 'observed in', 'True positive', 'False positive'],
    ...knowledge,
  },
  {
    path: '/dashboard/events/observed_data',
    label: 'Observed datas',
    icon: <WifiTetheringOutlined fontSize="small" />,
    keywords: ['telemetry', 'raw observation', 'Logs', 'evidence'],
    ...knowledge,
  },
];

export default menuEntries;

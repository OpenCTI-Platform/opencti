import { TrackChanges } from '@mui/icons-material';
import type { MenuEntry } from '../common/menus/menuEntry';
import { PIRAPI } from '../../../utils/hooks/capabilities';

export const pir: MenuEntry = {
  // One PIR concept: the left menu opens the intelligence requirements; /dashboard/pirs redirects there.
  path: '/dashboard/intelligence_requirements',
  label: 'Intelligence requirements',
  icon: <TrackChanges />,
  keywords: ['pir', 'priority', 'intelligence', 'requirement', 'watchlist', 'relevance'],
  requiredCapabilities: [PIRAPI],
};

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [pir];

export default menuEntries;

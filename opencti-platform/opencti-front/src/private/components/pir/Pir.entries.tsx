import { TrackChanges } from '@mui/icons-material';
import type { MenuEntry } from '../common/menus/menuEntry';
import { PIRAPI } from '../../../utils/hooks/capabilities';

export const pir: MenuEntry = { path: '/dashboard/pirs', label: 'PIR', icon: <TrackChanges />, requiredCapabilities: [PIRAPI] };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [pir];

export default menuEntries;

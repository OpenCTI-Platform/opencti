import { Home } from '@mui/icons-material';
import type { MenuEntry } from '../common/menus/menuEntry';

export const home: MenuEntry = { path: '/dashboard', label: 'Home', icon: <Home />, exact: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [home];

export default menuEntries;

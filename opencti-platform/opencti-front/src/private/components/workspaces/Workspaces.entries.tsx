import { ExploreOutlined } from '@mui/icons-material';
import type { MenuEntry } from '../common/menus/menuEntry';
import { EXPLORE, INVESTIGATION } from '../../../utils/hooks/capabilities';

export const customDashboards: MenuEntry = { path: '/dashboard/workspaces/dashboards', label: 'Custom dashboards', requiredCapabilities: [EXPLORE] };
export const publicDashboards: MenuEntry = { path: '/dashboard/workspaces/dashboards_public', label: 'Public dashboards', requiredCapabilities: [EXPLORE] };
export const investigations: MenuEntry = {
  path: '/dashboard/workspaces/investigations',
  label: 'Investigations',
  icon: <ExploreOutlined />,
  requiredCapabilities: [INVESTIGATION],
};

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [customDashboards, publicDashboards, investigations];

export default menuEntries;

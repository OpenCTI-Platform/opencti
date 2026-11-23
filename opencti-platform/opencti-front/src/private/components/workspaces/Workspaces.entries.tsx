import { Icon } from '@filigran/design-system';
import type { MenuEntry } from '../common/menus/menuEntry';
import { EXPLORE, INVESTIGATION } from '../../../utils/hooks/capabilities';

export const customDashboards: MenuEntry = {
  path: '/dashboard/workspaces/dashboards',
  label: 'Custom dashboards',
  entityType: 'Dashboard',
  keywords: ['Widget', 'Visualization', 'chart', 'kpi', 'Metrics'],
  requiredCapabilities: [EXPLORE],
};
export const publicDashboards: MenuEntry = {
  path: '/dashboard/workspaces/dashboards_public',
  label: 'Public dashboards',
  entityType: 'Dashboard',
  keywords: ['Shared', 'link', 'embed'],
  requiredCapabilities: [EXPLORE],
};
export const investigations: MenuEntry = {
  path: '/dashboard/workspaces/investigations',
  label: 'Investigations',
  keywords: ['Graph', 'pivot', 'hunting', 'canvas', 'link', 'Analysis'],
  icon: <Icon name="waypoints" size={16} />,
  requiredCapabilities: [INVESTIGATION],
};

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [customDashboards, publicDashboards, investigations];

export default menuEntries;

import type { MenuEntry } from '../../common/menus/NavToolbarMenu';
import { BYPASS } from '../../../../utils/hooks/capabilities';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
export const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/data/health/operations',
    label: 'Operations',
    keywords: ['health', 'sanity', 'data quality', 'integrity'],
    // Same rule as the left nav (useNavMenu).
    requiredCapabilities: [BYPASS],
    featureFlag: 'DATA_SANITY_MANAGER',
  },
];

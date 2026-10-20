import type { MenuEntry } from '../common/menus/NavToolbarMenu';
import { AUTOMATION_AUTMANAGE, CSVMAPPERS, KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
export const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/data/processing/automation',
    label: 'Automation',
    keywords: ['playbook', 'workflow', 'trigger'],
    requiredCapabilities: [AUTOMATION_AUTMANAGE],
    isEE: true,
  },
  {
    path: '/dashboard/data/processing/tasks',
    label: 'Tasks',
    keywords: ['background task', 'bulk', 'mass update', 'job'],
    requiredCapabilities: [KNOWLEDGE_KNUPDATE],
  },
  {
    path: '/dashboard/data/processing/csv_mapper',
    label: 'CSV Mappers',
    keywords: ['import', 'mapping', 'csv'],
    requiredCapabilities: [CSVMAPPERS],
  },
  {
    path: '/dashboard/data/processing/json_mapper',
    label: 'JSON Mappers',
    keywords: ['import', 'mapping', 'json'],
    requiredCapabilities: [CSVMAPPERS],
  },
];

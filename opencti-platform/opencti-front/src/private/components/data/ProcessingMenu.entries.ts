import type { MenuEntry } from '../common/menus/menuEntry';
import { AUTOMATION_AUTMANAGE, CSVMAPPERS, KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/capabilities';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/data/processing/automation',
    label: 'Automation',
    keywords: ['SOAR', 'orchestration', 'automation rule', 'automate', 'pipeline', 'no-code', 'Enrichment', 'Playbook', 'Workflow', 'Trigger'],
    requiredCapabilities: [AUTOMATION_AUTMANAGE],
    isEE: true,
  },
  {
    path: '/dashboard/data/processing/tasks',
    label: 'Tasks',
    keywords: ['bulk edit', 'batch', 'queue', 'running tasks', 'progress', 'mass delete', 'background task', 'mass update', 'job'],
    requiredCapabilities: [KNOWLEDGE_KNUPDATE],
  },
  {
    path: '/dashboard/data/processing/csv_mapper',
    label: 'CSV Mappers',
    keywords: ['parser', 'column mapping', 'spreadsheet', 'excel', 'ingest', 'csv import'],
    requiredCapabilities: [CSVMAPPERS],
  },
  {
    path: '/dashboard/data/processing/json_mapper',
    label: 'JSON Mappers',
    keywords: ['parser', 'field mapping', 'api feed', 'ingest', 'json import'],
    requiredCapabilities: [CSVMAPPERS],
  },
];

export default menuEntries;

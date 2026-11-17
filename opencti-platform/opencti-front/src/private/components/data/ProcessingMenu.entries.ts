import type { MenuEntry } from '../common/menus/menuEntry';
import { AUTOMATION_AUTMANAGE, CSVMAPPERS, KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/capabilities';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/data/processing/automation',
    label: 'Automation',
    keywords: ['Playbook', 'Workflow', 'Trigger', 'SOAR', 'orchestration', 'automate', 'pipeline', 'Enrichment'],
    requiredCapabilities: [AUTOMATION_AUTMANAGE],
    isEE: true,
  },
  {
    path: '/dashboard/data/processing/tasks',
    label: 'Tasks',
    keywords: ['bulk', 'batch', 'queue', 'mass', 'job', 'background'],
    requiredCapabilities: [KNOWLEDGE_KNUPDATE],
  },
  {
    path: '/dashboard/data/processing/csv_mapper',
    label: 'CSV Mappers',
    keywords: ['Import', 'Mapping', 'parser', 'spreadsheet', 'excel', 'Ingestion'],
    requiredCapabilities: [CSVMAPPERS],
  },
  {
    path: '/dashboard/data/processing/json_mapper',
    label: 'JSON Mappers',
    keywords: ['Import', 'Mapping', 'parser', 'api', 'Ingestion'],
    requiredCapabilities: [CSVMAPPERS],
  },
];

export default menuEntries;

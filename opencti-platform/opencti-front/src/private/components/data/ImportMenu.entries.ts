import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE_KNASKIMPORT, KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/capabilities';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/data/import/file',
    label: 'Global files',
    keywords: ['attachment', 'Ingestion', 'import file', 'txt', 'HTML', 'JSON', 'bundle', 'Upload', 'stix', 'pdf', 'document'],
    // Same rule as data/import/Root.tsx: draft-only users (KNUPDATE without KNASKIMPORT) only get /draft.
    requiredCapabilities: [KNOWLEDGE_KNASKIMPORT],
  },
  {
    path: '/dashboard/data/import/draft',
    label: 'Drafts',
    keywords: ['Pending', 'approval', 'validation', 'quarantine', 'Preview', 'unpublished', 'change set', 'four eyes', 'Staging', 'sandbox'],
    // Same rule as the left nav (useNavMenu): KNASKIMPORT, or KNUPDATE in main or draft.
    requiredCapabilities: [KNOWLEDGE_KNASKIMPORT, KNOWLEDGE_KNUPDATE],
    capabilitiesInDraft: [KNOWLEDGE_KNUPDATE],
  },
  {
    path: '/dashboard/data/import/workbench',
    label: 'Analyst workbenches',
    keywords: ['parse', 'ioc extraction', 'curation', 'triage', 'review import', 'Validate', 'pending import'],
    requiredCapabilities: [KNOWLEDGE_KNASKIMPORT],
  },
];

export default menuEntries;

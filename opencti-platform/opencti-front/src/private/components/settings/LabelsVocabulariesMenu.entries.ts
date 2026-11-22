import type { MenuEntry } from '../common/menus/menuEntry';
import {
  SETTINGS_SETCASETEMPLATES,
  SETTINGS_SETCUSTOMFIELDS,
  SETTINGS_SETKILLCHAINPHASES,
  SETTINGS_SETLABELS,
  SETTINGS_SETSTATUSTEMPLATES,
  SETTINGS_SETVOCABULARIES,
} from '../../../utils/hooks/capabilities';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/settings/vocabularies/labels',
    label: 'Labels',
    keywords: ['Tags', 'tagging', 'Taxonomy'],
    requiredCapabilities: [SETTINGS_SETLABELS],
  },
  {
    path: '/dashboard/settings/vocabularies/kill_chain_phases',
    label: 'Kill chain phases',
    keywords: ['stage', 'mitre', 'att&ck', 'attack', 'tactic', 'lockheed', 'unified', 'Taxonomy'],
    requiredCapabilities: [SETTINGS_SETKILLCHAINPHASES],
  },
  {
    path: '/dashboard/settings/vocabularies/fields',
    label: 'Vocabularies',
    keywords: ['picklist', 'Values', 'dropdown', 'enum', 'ov', 'Taxonomy'],
    requiredCapabilities: [SETTINGS_SETVOCABULARIES],
  },
  {
    path: '/dashboard/settings/vocabularies/status_templates',
    label: 'Status templates',
    keywords: ['Lifecycle', 'Workflow', 'States', 'Taxonomy'],
    requiredCapabilities: [SETTINGS_SETSTATUSTEMPLATES],
  },
  {
    path: '/dashboard/settings/vocabularies/case_templates',
    label: 'Case templates',
    keywords: ['runbook', 'procedure', 'checklist', 'Task', 'Playbook', 'Taxonomy'],
    requiredCapabilities: [SETTINGS_SETCASETEMPLATES],
  },
  {
    path: '/dashboard/settings/vocabularies/custom_fields',
    label: 'Custom fields',
    keywords: ['Attributes', 'extra', 'additional', 'schema', 'Taxonomy'],
    requiredCapabilities: [SETTINGS_SETCUSTOMFIELDS],
  },
];

export default menuEntries;

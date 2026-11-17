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
    keywords: ['tagging', 'taxonomy', 'keyword', 'Tags'],
    requiredCapabilities: [SETTINGS_SETLABELS],
  },
  {
    path: '/dashboard/settings/vocabularies/kill_chain_phases',
    label: 'Kill chain phases',
    keywords: ['cyber kill chain', 'stage', 'attack phase', 'unified kill chain', 'mitre', 'att&ck', 'tactic', 'lockheed'],
    requiredCapabilities: [SETTINGS_SETKILLCHAINPHASES],
  },
  {
    path: '/dashboard/settings/vocabularies/fields',
    label: 'Vocabularies',
    keywords: ['picklist', 'list of values', 'taxonomy', 'reference values', 'open vocabulary', 'dropdown values', 'enum'],
    requiredCapabilities: [SETTINGS_SETVOCABULARIES],
  },
  {
    path: '/dashboard/settings/vocabularies/status_templates',
    label: 'Status templates',
    keywords: ['Lifecycle', 'workflow states'],
    requiredCapabilities: [SETTINGS_SETSTATUSTEMPLATES],
  },
  {
    path: '/dashboard/settings/vocabularies/case_templates',
    label: 'Case templates',
    keywords: ['runbook', 'procedure', 'checklist', 'Task', 'Playbook', 'Incident response'],
    requiredCapabilities: [SETTINGS_SETCASETEMPLATES],
  },
  {
    path: '/dashboard/settings/vocabularies/custom_fields',
    label: 'Custom fields',
    keywords: ['custom attribute', 'extra field', 'additional field', 'schema'],
    requiredCapabilities: [SETTINGS_SETCUSTOMFIELDS],
  },
];

export default menuEntries;

import type { MenuEntry } from '../common/menus/NavToolbarMenu';
import {
  SETTINGS_SETCASETEMPLATES,
  SETTINGS_SETCUSTOMIZATION,
  SETTINGS_SETKILLCHAINPHASES,
  SETTINGS_SETLABELS,
  SETTINGS_SETSTATUSTEMPLATES,
  SETTINGS_SETVOCABULARIES,
} from '../../../utils/hooks/useGranted';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
export const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/settings/vocabularies/labels',
    label: 'Labels',
    keywords: ['tag', 'tags'],
    requiredCapabilities: [SETTINGS_SETLABELS],
  },
  {
    path: '/dashboard/settings/vocabularies/kill_chain_phases',
    label: 'Kill chain phases',
    keywords: ['mitre', 'att&ck', 'tactic', 'lockheed'],
    requiredCapabilities: [SETTINGS_SETKILLCHAINPHASES],
  },
  {
    path: '/dashboard/settings/vocabularies/fields',
    label: 'Vocabularies',
    keywords: ['open vocabulary', 'ov', 'dropdown values', 'enum'],
    requiredCapabilities: [SETTINGS_SETVOCABULARIES],
  },
  {
    path: '/dashboard/settings/vocabularies/status_templates',
    label: 'Status templates',
    keywords: ['workflow', 'status'],
    requiredCapabilities: [SETTINGS_SETSTATUSTEMPLATES],
  },
  {
    path: '/dashboard/settings/vocabularies/case_templates',
    label: 'Case templates',
    keywords: ['task', 'playbook', 'incident response'],
    requiredCapabilities: [SETTINGS_SETCASETEMPLATES],
  },
  {
    path: '/dashboard/settings/vocabularies/custom_fields',
    label: 'Custom fields',
    keywords: ['attribute', 'schema'],
    requiredCapabilities: [SETTINGS_SETCUSTOMIZATION],
    featureFlag: 'CUSTOM_FIELDS',
  },
];

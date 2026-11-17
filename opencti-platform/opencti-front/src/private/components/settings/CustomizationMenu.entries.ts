import type { MenuEntry } from '../common/menus/menuEntry';
import { SETTINGS_SETCUSTOMIZATION } from '../../../utils/hooks/capabilities';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/settings/customization/entity_types',
    label: 'Entity types',
    keywords: ['Customization', 'Data model', 'mandatory fields', 'default values', 'Form', 'Layout', 'schema', 'Attributes', 'Workflow', 'Custom Views'],
    requiredCapabilities: [SETTINGS_SETCUSTOMIZATION],
  },
  {
    path: '/dashboard/settings/customization/rules',
    label: 'Rules engine',
    keywords: ['reasoning', 'propagation', 'correlation', 'graph inference', 'automatic relationships'],
    requiredCapabilities: [SETTINGS_SETCUSTOMIZATION],
  },
  {
    path: '/dashboard/settings/customization/notifiers',
    label: 'Notifiers',
    keywords: ['slack', 'teams', 'outgoing notification', 'Channel', 'webhook', 'Email', 'alert'],
    requiredCapabilities: [SETTINGS_SETCUSTOMIZATION],
  },
  {
    path: '/dashboard/settings/customization/retention',
    label: 'Retention policies',
    keywords: ['data lifecycle', 'auto-delete', 'gdpr', 'cleanup', 'purge', 'expire'],
    requiredCapabilities: [SETTINGS_SETCUSTOMIZATION],
  },
  {
    path: '/dashboard/settings/customization/decay',
    label: 'Decay rules',
    keywords: ['aging', 'indicator lifecycle', 'score decay', 'Valid until', 'ioc expiration', 'Revoke', 'ttl'],
    requiredCapabilities: [SETTINGS_SETCUSTOMIZATION],
  },
  {
    path: '/dashboard/settings/customization/fintel_designs',
    label: 'Fintel design',
    keywords: ['finished intelligence', 'branding', 'logo', 'report design', 'export design', 'Template', 'pdf', 'Layout'],
    requiredCapabilities: [SETTINGS_SETCUSTOMIZATION],
    isEE: true,
  },
  {
    path: '/dashboard/settings/customization/exclusion_lists',
    label: 'Exclusion lists',
    keywords: ['warninglist', 'safelist', 'benign', 'top domains', 'noise reduction', 'allowlist', 'whitelist', 'False positive'],
    requiredCapabilities: [SETTINGS_SETCUSTOMIZATION],
  },
];

export default menuEntries;

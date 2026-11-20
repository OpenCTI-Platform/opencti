import type { MenuEntry } from '../common/menus/menuEntry';
import { SETTINGS_SETCUSTOMIZATION } from '../../../utils/hooks/capabilities';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/settings/customization/entity_types',
    label: 'Entity types',
    keywords: ['schema', 'Attributes', 'Custom', 'views', 'model', 'Mandatory', 'default', 'FORM', 'Layout', 'Workflow'],
    requiredCapabilities: [SETTINGS_SETCUSTOMIZATION],
  },
  {
    path: '/dashboard/settings/customization/rules',
    label: 'Rules engine',
    keywords: ['inference', 'reasoning', 'propagation', 'correlation', 'Automatic'],
    requiredCapabilities: [SETTINGS_SETCUSTOMIZATION],
  },
  {
    path: '/dashboard/settings/customization/notifiers',
    label: 'Notifiers',
    keywords: ['slack', 'teams', 'webhook', 'Email', 'alert'],
    requiredCapabilities: [SETTINGS_SETCUSTOMIZATION],
  },
  {
    path: '/dashboard/settings/customization/retention',
    label: 'Retention policies',
    keywords: ['policy', 'Lifecycle', 'delete', 'gdpr', 'cleanup', 'purge', 'expire'],
    requiredCapabilities: [SETTINGS_SETCUSTOMIZATION],
  },
  {
    path: '/dashboard/settings/customization/decay',
    label: 'Decay rules',
    keywords: ['aging', 'Lifecycle', 'Score', 'Expiration', 'Revoke', 'ttl'],
    requiredCapabilities: [SETTINGS_SETCUSTOMIZATION],
  },
  {
    path: '/dashboard/settings/customization/fintel_designs',
    label: 'Fintel design',
    keywords: ['finint', 'Branding', 'logo', 'Template', 'pdf', 'Report'],
    requiredCapabilities: [SETTINGS_SETCUSTOMIZATION],
    isEE: true,
  },
  {
    path: '/dashboard/settings/customization/exclusion_lists',
    label: 'Exclusion lists',
    keywords: ['allowlist', 'whitelist', 'safelist', 'benign', 'noise', 'False', 'positive'],
    requiredCapabilities: [SETTINGS_SETCUSTOMIZATION],
  },
];

export default menuEntries;

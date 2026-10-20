import type { MenuEntry } from '../common/menus/NavToolbarMenu';
import { SETTINGS_SETCUSTOMIZATION } from '../../../utils/hooks/useGranted';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
export const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/settings/customization/entity_types',
    label: 'Entity types',
    keywords: ['schema', 'attributes', 'custom fields', 'workflow', 'custom views'],
    requiredCapabilities: [SETTINGS_SETCUSTOMIZATION],
  },
  {
    path: '/dashboard/settings/customization/rules',
    label: 'Rules engine',
    keywords: ['inference', 'automatic relationships'],
    requiredCapabilities: [SETTINGS_SETCUSTOMIZATION],
  },
  {
    path: '/dashboard/settings/customization/notifiers',
    label: 'Notifiers',
    keywords: ['notification', 'webhook', 'email', 'alert'],
    requiredCapabilities: [SETTINGS_SETCUSTOMIZATION],
  },
  {
    path: '/dashboard/settings/customization/retention',
    label: 'Retention policies',
    keywords: ['delete', 'cleanup', 'purge', 'expire'],
    requiredCapabilities: [SETTINGS_SETCUSTOMIZATION],
  },
  {
    path: '/dashboard/settings/customization/decay',
    label: 'Decay rules',
    keywords: ['indicator', 'score', 'expiration', 'revoke', 'ttl'],
    requiredCapabilities: [SETTINGS_SETCUSTOMIZATION],
  },
  {
    path: '/dashboard/settings/customization/fintel_designs',
    label: 'Fintel design',
    keywords: ['template', 'pdf', 'report', 'layout'],
    requiredCapabilities: [SETTINGS_SETCUSTOMIZATION],
    isEE: true,
  },
  {
    path: '/dashboard/settings/customization/exclusion_lists',
    label: 'Exclusion lists',
    keywords: ['allowlist', 'whitelist', 'false positive', 'ignore'],
    requiredCapabilities: [SETTINGS_SETCUSTOMIZATION],
  },
];

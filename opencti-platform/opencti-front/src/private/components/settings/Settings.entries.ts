import type { MenuEntry } from '../common/menus/menuEntry';
import { SETTINGS_FILEINDEXING, SETTINGS_SETMANAGEXTMHUB, SETTINGS_SETPARAMETERS, SETTINGS_SUPPORT } from '../../../utils/hooks/capabilities';

export const parameters: MenuEntry = {
  path: '/dashboard/settings',
  label: 'Parameters',
  keywords: ['Configuration', 'administration', 'License', 'Enterprise', 'Edition'],
  exact: true,
  requiredCapabilities: [SETTINGS_SETPARAMETERS],
};
export const fileIndexing: MenuEntry = {
  path: '/dashboard/settings/file_indexing',
  label: 'File indexing',
  keywords: ['search', 'document', 'Attachment', 'Text', 'full'],
  requiredCapabilities: [SETTINGS_FILEINDEXING],
};
export const experience: MenuEntry = {
  path: '/dashboard/settings/experience',
  label: 'Filigran Experience',
  keywords: ['xtm', 'hub', 'ai', 'artificial', 'llm', 'Assistant', 'copilot', 'ariane', 'License'],
  requiredCapabilities: [SETTINGS_SETPARAMETERS, SETTINGS_SUPPORT, SETTINGS_SETMANAGEXTMHUB],
};

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
// The Settings pages with their own toolbar (security, customization...) are declared next to their menu.
const menuEntries: MenuEntry[] = [parameters, fileIndexing, experience];

export default menuEntries;

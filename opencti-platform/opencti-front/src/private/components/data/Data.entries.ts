import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../utils/hooks/capabilities';

export const dataEntities: MenuEntry = {
  path: '/dashboard/data/entities',
  label: 'Entities',
  keywords: ['all objects', 'sdo', 'stix domain object', 'data browser', 'Explore', 'inventory', 'threat library', 'intelligence card'],
  requiredCapabilities: [KNOWLEDGE],
  availableInDraft: true,
};
export const dataRelationships: MenuEntry = {
  path: '/dashboard/data/relationships',
  label: 'Relationships',
  keywords: ['link', 'edge', 'sro', 'association', 'connection', 'correlation', 'uses', 'targets', 'attributed-to'],
  requiredCapabilities: [KNOWLEDGE],
  availableInDraft: true,
};
// Also needs the trash enabled in the platform settings: not a page rule, checked by the left bar.
export const trash: MenuEntry = {
  path: '/dashboard/trash',
  label: 'Trash',
  keywords: ['deleted', 'recycle bin', 'Restore', 'undelete', 'recover'],
  requiredCapabilities: [KNOWLEDGE_KNUPDATE_KNDELETE],
};

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
// The Data pages with their own toolbar (import, processing...) are declared next to their menu.
const menuEntries: MenuEntry[] = [dataEntities, dataRelationships, trash];

export default menuEntries;

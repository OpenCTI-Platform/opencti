import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../utils/hooks/capabilities';

export const dataEntities: MenuEntry = { path: '/dashboard/data/entities', label: 'Entities', requiredCapabilities: [KNOWLEDGE], availableInDraft: true };
export const dataRelationships: MenuEntry = { path: '/dashboard/data/relationships', label: 'Relationships', requiredCapabilities: [KNOWLEDGE], availableInDraft: true };
// Also needs the trash enabled in the platform settings: not a page rule, checked by the left bar.
export const trash: MenuEntry = { path: '/dashboard/trash', label: 'Trash', requiredCapabilities: [KNOWLEDGE_KNUPDATE_KNDELETE] };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
// The Data pages with their own toolbar (import, processing...) are declared next to their menu.
const menuEntries: MenuEntry[] = [dataEntities, dataRelationships, trash];

export default menuEntries;

import { ArchiveOutline, HexagonOutline, ServerNetwork, ShieldSearch } from 'mdi-material-ui';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  { path: '/dashboard/observations/observables', label: 'Observables', icon: <HexagonOutline fontSize="small" />, ...knowledge },
  { path: '/dashboard/observations/artifacts', label: 'Artifacts', icon: <ArchiveOutline fontSize="small" />, ...knowledge },
  { path: '/dashboard/observations/indicators', label: 'Indicators', icon: <ShieldSearch fontSize="small" />, ...knowledge },
  { path: '/dashboard/observations/infrastructures', label: 'Infrastructures', icon: <ServerNetwork fontSize="small" />, ...knowledge },
];

export default menuEntries;

import { ExtensionOutlined } from '@mui/icons-material';
import type { MenuEntry } from '../common/menus/menuEntry';
import { INGESTION, INGESTION_SETINGESTIONS, MODULES } from '../../../utils/hooks/capabilities';

export const integrations: MenuEntry = {
  path: '/dashboard/integrations',
  label: 'Integrations',
  keywords: ['Connector', 'marketplace', 'application', 'plugin', 'Enrichment', 'Ingestion', 'xtm', 'hub'],
  icon: <ExtensionOutlined />,
  requiredCapabilities: [MODULES, INGESTION, INGESTION_SETINGESTIONS],
};

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [integrations];

export default menuEntries;

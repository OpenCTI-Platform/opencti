import { BugReportOutlined, SurroundSoundOutlined, WebAssetOutlined } from '@mui/icons-material';
import { Biohazard } from 'mdi-material-ui';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  { path: '/dashboard/arsenal/malwares', label: 'Malwares', icon: <Biohazard fontSize="small" />, ...knowledge },
  { path: '/dashboard/arsenal/channels', label: 'Channels', icon: <SurroundSoundOutlined fontSize="small" />, ...knowledge },
  { path: '/dashboard/arsenal/tools', label: 'Tools', icon: <WebAssetOutlined fontSize="small" />, ...knowledge },
  {
    path: '/dashboard/arsenal/vulnerabilities',
    label: 'Vulnerabilities',
    icon: <BugReportOutlined fontSize="small" />,
    keywords: ['cve', 'cvss', 'exploit', 'weakness'],
    ...knowledge,
  },
];

export default menuEntries;

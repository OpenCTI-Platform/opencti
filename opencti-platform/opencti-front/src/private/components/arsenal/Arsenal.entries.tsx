import { BugReportOutlined, SurroundSoundOutlined, WebAssetOutlined } from '@mui/icons-material';
import { Biohazard } from 'mdi-material-ui';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/arsenal/malwares',
    label: 'Malwares',
    icon: <Biohazard fontSize="small" />,
    keywords: ['malware family', 'ransomware', 'remote access trojan', 'backdoor', 'loader', 'infostealer', 'botnet', 'Implant', 'virus'],
    ...knowledge,
  },
  {
    path: '/dashboard/arsenal/channels',
    label: 'Channels',
    icon: <SurroundSoundOutlined fontSize="small" />,
    keywords: ['telegram', 'discord', 'forum', 'dark web', 'deep web', 'social media', 'paste site', 'marketplace', 'communication'],
    ...knowledge,
  },
  {
    path: '/dashboard/arsenal/tools',
    label: 'Tools',
    icon: <WebAssetOutlined fontSize="small" />,
    keywords: ['software', 'hacktool', 'dual-use', 'lolbin', 'living off the land', 'cobalt strike', 'mimikatz', 'utility'],
    ...knowledge,
  },
  {
    path: '/dashboard/arsenal/vulnerabilities',
    label: 'Vulnerabilities',
    icon: <BugReportOutlined fontSize="small" />,
    keywords: ['Vulnerability', 'epss', 'CISA KEV', 'cwe', 'cpe', 'nvd', 'zero-day', '0day', 'patch', 'advisory', 'cve', 'cvss', 'exploit', 'weakness'],
    ...knowledge,
  },
];

export default menuEntries;

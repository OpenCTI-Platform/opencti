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
    entityType: 'Malware',
    icon: <Biohazard fontSize="small" />,
    keywords: ['ransomware', 'trojan', 'rat', 'backdoor', 'loader', 'infostealer', 'botnet', 'Implant', 'virus'],
    ...knowledge,
  },
  {
    path: '/dashboard/arsenal/channels',
    label: 'Channels',
    entityType: 'Channel',
    icon: <SurroundSoundOutlined fontSize="small" />,
    keywords: ['telegram', 'discord', 'forum', 'darkweb', 'social', 'Paste'],
    ...knowledge,
  },
  {
    path: '/dashboard/arsenal/tools',
    label: 'Tools',
    entityType: 'Tool',
    icon: <WebAssetOutlined fontSize="small" />,
    keywords: ['software', 'hacktool', 'dual', 'lolbin', 'lotl', 'living', 'cobalt', 'mimikatz'],
    ...knowledge,
  },
  {
    path: '/dashboard/arsenal/vulnerabilities',
    label: 'Vulnerabilities',
    entityType: 'Vulnerability',
    icon: <BugReportOutlined fontSize="small" />,
    keywords: ['Vulnerability', 'cve', 'cvss', 'epss', 'kev', 'cisa', 'cwe', 'CPE', 'nvd', 'exploit', 'weakness', 'patch', 'advisory', '0day', 'zero'],
    ...knowledge,
  },
];

export default menuEntries;

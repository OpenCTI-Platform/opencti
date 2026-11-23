import { Icon } from '@filigran/design-system';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/arsenal/malwares',
    label: 'Malwares',
    entityType: 'Malware',
    icon: <Icon name="custom/malware" size={16} />,
    keywords: ['ransomware', 'trojan', 'rat', 'backdoor', 'loader', 'infostealer', 'botnet', 'Implant', 'virus'],
    ...knowledge,
  },
  {
    path: '/dashboard/arsenal/channels',
    label: 'Channels',
    entityType: 'Channel',
    icon: <Icon name="megaphone" size={16} />,
    keywords: ['telegram', 'discord', 'forum', 'darkweb', 'social', 'Paste'],
    ...knowledge,
  },
  {
    path: '/dashboard/arsenal/tools',
    label: 'Tools',
    entityType: 'Tool',
    icon: <Icon name="wrench" size={16} />,
    keywords: ['software', 'hacktool', 'dual', 'lolbin', 'lotl', 'living', 'cobalt', 'mimikatz'],
    ...knowledge,
  },
  {
    path: '/dashboard/arsenal/vulnerabilities',
    label: 'Vulnerabilities',
    entityType: 'Vulnerability',
    icon: <Icon name="bug" size={16} />,
    keywords: ['Vulnerability', 'cve', 'cvss', 'epss', 'kev', 'cisa', 'cwe', 'CPE', 'nvd', 'exploit', 'weakness', 'patch', 'advisory', '0day', 'zero'],
    ...knowledge,
  },
];

export default menuEntries;

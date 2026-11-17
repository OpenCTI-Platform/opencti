import { ArchiveOutline, HexagonOutline, ServerNetwork, ShieldSearch } from 'mdi-material-ui';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/observations/observables',
    label: 'Observables',
    icon: <HexagonOutline fontSize="small" />,
    keywords: ['sco', 'cyber observable', 'Attribute', 'ipv4', 'Domain', 'Hostname', 'URL', 'hash', 'md5', 'sha256', 'Email address', 'technical data'],
    ...knowledge,
  },
  {
    path: '/dashboard/observations/artifacts',
    label: 'Artifacts',
    icon: <ArchiveOutline fontSize="small" />,
    keywords: ['malware sample', 'file sample', 'binary', 'payload', 'download sample'],
    ...knowledge,
  },
  {
    path: '/dashboard/observations/indicators',
    label: 'Indicators',
    icon: <ShieldSearch fontSize="small" />,
    keywords: ['iocs', 'indicator of compromise', 'detection rule', 'signature', 'yara', 'sigma', 'snort', 'suricata', 'stix pattern', 'blocklist'],
    ...knowledge,
  },
  {
    path: '/dashboard/observations/infrastructures',
    label: 'Infrastructures',
    icon: <ServerNetwork fontSize="small" />,
    keywords: ['c2', 'c&c', 'command and control', 'adversary infrastructure', 'Server', 'hosting', 'botnet'],
    ...knowledge,
  },
];

export default menuEntries;

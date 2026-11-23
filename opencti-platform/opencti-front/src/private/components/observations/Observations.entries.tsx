import { Icon } from '@filigran/design-system';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/observations/observables',
    label: 'Observables',
    entityType: 'Stix-Cyber-Observable',
    icon: <Icon name="hexagon" size={16} />,
    keywords: ['sco', 'ipv4', 'ipv6', 'Domain', 'Hostname', 'URL', 'Hash', 'MD5', 'sha256', 'Email'],
    ...knowledge,
  },
  {
    path: '/dashboard/observations/artifacts',
    label: 'Artifacts',
    entityType: 'Artifact',
    icon: <Icon name="box" size={16} />,
    keywords: ['Sample', 'Malware', 'binary', 'Payload'],
    ...knowledge,
  },
  {
    path: '/dashboard/observations/indicators',
    label: 'Indicators',
    entityType: 'Indicator',
    icon: <Icon name="file-search" size={16} />,
    keywords: ['iocs', 'compromise', 'signature', 'yara', 'sigma', 'snort', 'suricata', 'pattern', 'blocklist'],
    ...knowledge,
  },
  {
    path: '/dashboard/observations/infrastructures',
    label: 'Infrastructures',
    entityType: 'Infrastructure',
    icon: <Icon name="custom/infrastructure" size={16} />,
    keywords: ['c2', 'c&c', 'command', 'Control', 'hosting', 'botnet', 'Server'],
    ...knowledge,
  },
];

export default menuEntries;

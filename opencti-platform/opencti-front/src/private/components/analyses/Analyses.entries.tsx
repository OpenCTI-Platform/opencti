import { Icon } from '@filigran/design-system';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/analyses/reports',
    label: 'Reports',
    entityType: 'Report',
    icon: <Icon name="file-text" size={16} />,
    keywords: ['finint', 'bulletin', 'advisory', 'Publication', 'Container', 'Analysis'],
    ...knowledge,
  },
  {
    path: '/dashboard/analyses/groupings',
    label: 'Groupings',
    entityType: 'Grouping',
    icon: <Icon name="layout-grid" size={16} />,
    keywords: ['bundle', 'Cluster', 'context', 'Analysis'],
    ...knowledge,
  },
  {
    path: '/dashboard/analyses/malware_analyses',
    label: 'Malware analyses',
    entityType: 'Malware-Analysis',
    icon: <Icon name="flask-conical" size={16} />,
    keywords: ['sandbox', 'detonation', 'dynamic', 'static', 'Reverse', 'engineering', 'Sample', 'verdict', 'Report', 'Analysis'],
    ...knowledge,
  },
  {
    path: '/dashboard/analyses/security_coverages',
    label: 'Security coverages',
    entityType: 'Security-Coverage',
    icon: <Icon name="shield-check" size={16} />,
    keywords: ['gap', 'Heatmap', 'defense', 'EDR', 'SIEM', 'mitre', 'Analysis'],
    ...knowledge,
  },
  {
    path: '/dashboard/analyses/notes',
    label: 'Notes',
    entityType: 'Note',
    icon: <Icon name="sticky-note" size={16} />,
    keywords: ['comment', 'annotation', 'Opinion', 'remark', 'assessment', 'Analysis'],
    ...knowledge,
  },
  {
    path: '/dashboard/analyses/external_references',
    label: 'External references',
    entityType: 'External-Reference',
    icon: <Icon name="external-link" size={16} />,
    keywords: ['URL', 'citation', 'article', 'blog', 'osint', 'Analysis'],
    ...knowledge,
  },
];

export default menuEntries;

import { BiotechOutlined, DescriptionOutlined, LocalOfferOutlined, SecurityOutlined, SubjectOutlined, WorkspacesOutlined } from '@mui/icons-material';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/analyses/reports',
    label: 'Reports',
    icon: <DescriptionOutlined fontSize="small" />,
    keywords: ['finished intelligence', 'finint', 'threat report', 'bulletin', 'advisory', 'Publication', 'Container'],
    ...knowledge,
  },
  {
    path: '/dashboard/analyses/groupings',
    label: 'Groupings',
    icon: <WorkspacesOutlined fontSize="small" />,
    keywords: ['bundle', 'Cluster', 'context', 'collection of objects', 'analysis in progress'],
    ...knowledge,
  },
  {
    path: '/dashboard/analyses/malware_analyses',
    label: 'Malware analyses',
    icon: <BiotechOutlined fontSize="small" />,
    keywords: ['sandbox', 'detonation', 'dynamic analysis', 'static analysis', 'reverse engineering', 'sample analysis', 'malware report', 'verdict'],
    ...knowledge,
  },
  {
    path: '/dashboard/analyses/security_coverages',
    label: 'Security coverages',
    icon: <SecurityOutlined fontSize="small" />,
    keywords: ['mitre coverage', 'gap analysis', 'Heatmap', 'detection rule', 'defense posture', 'EDR', 'SIEM'],
    ...knowledge,
  },
  {
    path: '/dashboard/analyses/notes',
    label: 'Notes',
    icon: <SubjectOutlined fontSize="small" />,
    keywords: ['comment', 'annotation', 'analyst note', 'Opinion', 'remark', 'assessment'],
    ...knowledge,
  },
  {
    path: '/dashboard/analyses/external_references',
    label: 'External references',
    icon: <LocalOfferOutlined fontSize="small" />,
    keywords: ['URL', 'link', 'citation', 'article', 'blog', 'osint source', 'bibliography'],
    ...knowledge,
  },
];

export default menuEntries;

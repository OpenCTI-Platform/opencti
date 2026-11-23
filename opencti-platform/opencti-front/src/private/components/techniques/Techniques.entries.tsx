import { Icon } from '@filigran/design-system';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/techniques/attack_patterns',
    label: 'Attack patterns',
    entityType: 'Attack-Pattern',
    icon: <Icon name="custom/attack-pattern" size={16} />,
    keywords: ['TTPs', 'mitre', 'att&ck', 'matrix', 'capec'],
    ...knowledge,
  },
  {
    path: '/dashboard/techniques/narratives',
    label: 'Narratives',
    entityType: 'Narrative',
    icon: <Icon name="message-square-more" size={16} />,
    keywords: ['disinformation', 'misinformation', 'propaganda', 'influence', 'fimi'],
    ...knowledge,
  },
  {
    path: '/dashboard/techniques/courses_of_action',
    label: 'Courses of action',
    entityType: 'Course-Of-Action',
    icon: <Icon name="custom/course-of-action" size={16} />,
    keywords: ['mitigation', 'remediation', 'countermeasure', 'defense', 'd3fend'],
    ...knowledge,
  },
  {
    path: '/dashboard/techniques/data_components',
    label: 'Data components',
    entityType: 'Data-Component',
    icon: <Icon name="layers-2" size={16} />,
    keywords: ['telemetry', 'Logs', 'source', 'mitre', 'Detection'],
    ...knowledge,
  },
  {
    path: '/dashboard/techniques/data_sources',
    label: 'Data sources',
    entityType: 'Data-Source',
    icon: <Icon name="file-input" size={16} />,
    keywords: ['telemetry', 'Logs', 'mitre', 'Visibility'],
    ...knowledge,
  },
];

export default menuEntries;

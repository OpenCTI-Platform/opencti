import { SourceOutlined, SpeakerNotesOutlined, StreamOutlined } from '@mui/icons-material';
import { LockPattern, ProgressWrench } from 'mdi-material-ui';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/techniques/attack_patterns',
    label: 'Attack patterns',
    entityType: 'Attack-Pattern',
    icon: <LockPattern fontSize="small" />,
    keywords: ['TTPs', 'sub-technique', 'mitre', 'att&ck', 'matrix', 'capec', 'behavior'],
    ...knowledge,
  },
  {
    path: '/dashboard/techniques/narratives',
    label: 'Narratives',
    entityType: 'Narrative',
    icon: <SpeakerNotesOutlined fontSize="small" />,
    keywords: ['disinformation', 'misinformation', 'influence operation', 'propaganda', 'fimi', 'info ops'],
    ...knowledge,
  },
  {
    path: '/dashboard/techniques/courses_of_action',
    label: 'Courses of action',
    entityType: 'Course-Of-Action',
    icon: <ProgressWrench fontSize="small" />,
    keywords: ['mitigation', 'remediation', 'countermeasure', 'recommendation', 'defense', 'd3fend'],
    ...knowledge,
  },
  {
    path: '/dashboard/techniques/data_components',
    label: 'Data components',
    entityType: 'Data-Component',
    icon: <SourceOutlined fontSize="small" />,
    keywords: ['telemetry', 'log source', 'mitre data component', 'Detection'],
    ...knowledge,
  },
  {
    path: '/dashboard/techniques/data_sources',
    label: 'Data sources',
    entityType: 'Data-Source',
    icon: <StreamOutlined fontSize="small" />,
    keywords: ['log source', 'telemetry source', 'mitre data source', 'Visibility'],
    ...knowledge,
  },
];

export default menuEntries;

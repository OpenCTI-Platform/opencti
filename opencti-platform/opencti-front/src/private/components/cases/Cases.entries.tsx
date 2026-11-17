import { TaskAltOutlined } from '@mui/icons-material';
import { BriefcaseEditOutline, BriefcaseEyeOutline, BriefcaseRemoveOutline, BriefcaseSearchOutline } from 'mdi-material-ui';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/cases/incidents',
    label: 'Incident responses',
    entityType: 'Case-Incident',
    icon: <BriefcaseEyeOutline fontSize="small" />,
    keywords: ['ir', 'dfir', 'ticket', 'soc'],
    ...knowledge,
  },
  {
    path: '/dashboard/cases/rfis',
    label: 'Requests for information',
    entityType: 'Case-Rfi',
    icon: <BriefcaseSearchOutline fontSize="small" />,
    keywords: ['rfi', 'question', 'tasking', 'requirement'],
    ...knowledge,
  },
  {
    path: '/dashboard/cases/rfts',
    label: 'Requests for takedown',
    entityType: 'Case-Rft',
    icon: <BriefcaseRemoveOutline fontSize="small" />,
    keywords: ['rft', 'removal', 'phishing', 'brand', 'abuse'],
    ...knowledge,
  },
  {
    path: '/dashboard/cases/tasks',
    label: 'Tasks',
    entityType: 'Task',
    icon: <TaskAltOutlined fontSize="small" />,
    keywords: ['todo', 'assignment', 'checklist'],
    ...knowledge,
  },
  {
    path: '/dashboard/cases/feedbacks',
    label: 'Feedbacks',
    entityType: 'Feedback',
    icon: <BriefcaseEditOutline fontSize="small" />,
    keywords: ['Rating', 'satisfaction', 'survey'],
    ...knowledge,
  },
];

export default menuEntries;

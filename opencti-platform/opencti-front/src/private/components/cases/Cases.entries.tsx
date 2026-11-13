import { TaskAltOutlined } from '@mui/icons-material';
import { BriefcaseEditOutline, BriefcaseEyeOutline, BriefcaseRemoveOutline, BriefcaseSearchOutline } from 'mdi-material-ui';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  { path: '/dashboard/cases/incidents', label: 'Incident responses', icon: <BriefcaseEyeOutline fontSize="small" />, ...knowledge },
  { path: '/dashboard/cases/rfis', label: 'Requests for information', icon: <BriefcaseSearchOutline fontSize="small" />, ...knowledge },
  { path: '/dashboard/cases/rfts', label: 'Requests for takedown', icon: <BriefcaseRemoveOutline fontSize="small" />, ...knowledge },
  { path: '/dashboard/cases/tasks', label: 'Tasks', icon: <TaskAltOutlined fontSize="small" />, ...knowledge },
  { path: '/dashboard/cases/feedbacks', label: 'Feedbacks', icon: <BriefcaseEditOutline fontSize="small" />, ...knowledge },
];

export default menuEntries;

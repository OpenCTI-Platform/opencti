import { Icon } from '@filigran/design-system';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/cases/incidents',
    label: 'Incident responses',
    entityType: 'Case-Incident',
    icon: <Icon name="custom/case-incident" size={16} />,
    keywords: ['ir', 'dfir', 'ticket', 'soc'],
    ...knowledge,
  },
  {
    path: '/dashboard/cases/rfis',
    label: 'Requests for information',
    entityType: 'Case-Rfi',
    icon: <Icon name="custom/case-rfi" size={16} />,
    keywords: ['rfi', 'question', 'tasking', 'requirement'],
    ...knowledge,
  },
  {
    path: '/dashboard/cases/rfts',
    label: 'Requests for takedown',
    entityType: 'Case-Rft',
    icon: <Icon name="custom/case-rft" size={16} />,
    keywords: ['rft', 'removal', 'phishing', 'brand', 'abuse'],
    ...knowledge,
  },
  {
    path: '/dashboard/cases/tasks',
    label: 'Tasks',
    entityType: 'Task',
    icon: <Icon name="list-checks" size={16} />,
    keywords: ['todo', 'assignment', 'checklist'],
    ...knowledge,
  },
  {
    path: '/dashboard/cases/feedbacks',
    label: 'Feedbacks',
    entityType: 'Feedback',
    icon: <Icon name="message-square-text" size={16} />,
    keywords: ['Rating', 'satisfaction', 'survey'],
    ...knowledge,
  },
];

export default menuEntries;

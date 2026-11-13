import { SourceOutlined, SpeakerNotesOutlined, StreamOutlined } from '@mui/icons-material';
import { LockPattern, ProgressWrench } from 'mdi-material-ui';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  { path: '/dashboard/techniques/attack_patterns', label: 'Attack patterns', icon: <LockPattern fontSize="small" />, ...knowledge },
  { path: '/dashboard/techniques/narratives', label: 'Narratives', icon: <SpeakerNotesOutlined fontSize="small" />, ...knowledge },
  { path: '/dashboard/techniques/courses_of_action', label: 'Courses of action', icon: <ProgressWrench fontSize="small" />, ...knowledge },
  { path: '/dashboard/techniques/data_components', label: 'Data components', icon: <SourceOutlined fontSize="small" />, ...knowledge },
  { path: '/dashboard/techniques/data_sources', label: 'Data sources', icon: <StreamOutlined fontSize="small" />, ...knowledge },
];

export default menuEntries;

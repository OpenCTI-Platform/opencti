import { BiotechOutlined, DescriptionOutlined, LocalOfferOutlined, SecurityOutlined, SubjectOutlined, WorkspacesOutlined } from '@mui/icons-material';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  { path: '/dashboard/analyses/reports', label: 'Reports', icon: <DescriptionOutlined fontSize="small" />, ...knowledge },
  { path: '/dashboard/analyses/groupings', label: 'Groupings', icon: <WorkspacesOutlined fontSize="small" />, ...knowledge },
  { path: '/dashboard/analyses/malware_analyses', label: 'Malware analyses', icon: <BiotechOutlined fontSize="small" />, ...knowledge },
  { path: '/dashboard/analyses/security_coverages', label: 'Security coverages', icon: <SecurityOutlined fontSize="small" />, ...knowledge },
  { path: '/dashboard/analyses/notes', label: 'Notes', icon: <SubjectOutlined fontSize="small" />, ...knowledge },
  { path: '/dashboard/analyses/external_references', label: 'External references', icon: <LocalOfferOutlined fontSize="small" />, ...knowledge },
];

export default menuEntries;

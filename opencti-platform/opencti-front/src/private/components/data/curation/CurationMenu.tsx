import NavToolbarMenu, { MenuEntry } from '@components/common/menus/NavToolbarMenu';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../../utils/hooks/useGranted';

const CurationMenu = () => {
  const isGrantedToSettings = useGranted([SETTINGS_SETPARAMETERS]);
  const entries: MenuEntry[] = [
    { path: '/dashboard/data/curation/proposals', label: 'Inbox' },
    { path: '/dashboard/data/curation/merges', label: 'Merge history' },
    { path: '/dashboard/data/curation/policies', label: 'Policies', isEE: true },
    { path: '/dashboard/data/curation/health', label: 'Knowledge Health' },
    ...(isGrantedToSettings ? [{ path: '/dashboard/data/curation/settings', label: 'Settings' }] : []),
  ];
  return <NavToolbarMenu entries={entries} />;
};

export default CurationMenu;

import NavToolbarMenu, { MenuEntry } from '@components/common/menus/NavToolbarMenu';
import { PATH_DISSEMINATION_ASSURANCE_LISTS, PATH_DISSEMINATION_ASSURANCE_OVERVIEW, PATH_DISSEMINATION_ASSURANCE_VALIDATIONS } from './disseminationAssuranceUtils';

const DisseminationAssuranceMenu = () => {
  const entries: MenuEntry[] = [
    { path: PATH_DISSEMINATION_ASSURANCE_OVERVIEW, label: 'Overview' },
    { path: PATH_DISSEMINATION_ASSURANCE_LISTS, label: 'Lists' },
    { path: PATH_DISSEMINATION_ASSURANCE_VALIDATIONS, label: 'Validation requests' },
  ];
  return <NavToolbarMenu entries={entries} />;
};

export default DisseminationAssuranceMenu;

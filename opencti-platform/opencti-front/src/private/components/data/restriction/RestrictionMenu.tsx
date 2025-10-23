import NavToolbarMenu, { MenuEntry } from '@components/common/menus/NavToolbarMenu';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

const RestrictionMenu = () => {
  const isEnterpriseEdition = useEnterpriseEdition();

  const entries: MenuEntry[] = [
    ...(isEnterpriseEdition ? [{
      path: '/dashboard/data/restriction/restricted',
      label: 'Restricted entities',
    }] : []),
    {
      path: '/dashboard/data/restriction/drafts',
      label: 'Restricted drafts',
    },
  ];
  return <NavToolbarMenu entries={entries} />;
};

export default RestrictionMenu;

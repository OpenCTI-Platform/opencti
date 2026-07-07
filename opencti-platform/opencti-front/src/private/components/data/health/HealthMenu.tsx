import NavToolbarMenu, { MenuEntry } from '@components/common/menus/NavToolbarMenu';

const HealthMenu = () => {
  const entries: MenuEntry[] = [
    {
      path: '/dashboard/data/health/operations',
      label: 'Operations',
    },
  ];
  return <NavToolbarMenu entries={entries} />;
};

export default HealthMenu;

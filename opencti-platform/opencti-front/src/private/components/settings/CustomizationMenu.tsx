import React, { FunctionComponent } from 'react';
import NavToolbarMenu, { MenuEntry } from '../common/menus/NavToolbarMenu';

const CustomizationMenu: FunctionComponent = () => {
  const entries: MenuEntry[] = [
    {
      path: '/dashboard/settings/customization/entity_types',
      label: 'Entity types',
    },
    {
      path: '/dashboard/settings/customization/rules',
      label: 'Rules engine',
    },
    {
      path: '/dashboard/settings/customization/notifiers',
      label: 'Notifiers',
    },
    {
      path: '/dashboard/settings/customization/retention',
      label: 'Retention policies',
    },
    {
      path: '/dashboard/settings/customization/decay',
      label: 'Decay rules',
    },
    {
      path: '/dashboard/settings/customization/exclusion_lists',
      label: 'Exclusion lists',
    },
  ];
  return <NavToolbarMenu entries={entries} />;
};

export default CustomizationMenu;

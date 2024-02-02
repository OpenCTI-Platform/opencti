import React, { FunctionComponent } from 'react';
import NavToolbarMenu, { MenuEntry } from '../common/menus/NavToolbarMenu';
import useHelper from '../../../utils/hooks/useHelper';

const CustomizationMenu: FunctionComponent = () => {
  const { isFeatureEnable } = useHelper();
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
    ...(isFeatureEnable('INDICATOR_DECAY') ? [{
      path: '/dashboard/settings/customization/decay',
      label: 'Decay rules',
    }] : []),
  ];
  return <NavToolbarMenu entries={entries} />;
};

export default CustomizationMenu;

import React, { FunctionComponent } from 'react';
import NavToolbarMenu from '../common/menus/NavToolbarMenu';
import { menuEntries } from './CustomizationMenu.entries';

const CustomizationMenu: FunctionComponent = () => <NavToolbarMenu entries={menuEntries} />;

export default CustomizationMenu;

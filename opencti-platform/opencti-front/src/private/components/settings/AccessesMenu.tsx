import React, { FunctionComponent } from 'react';
import NavToolbarMenu from '../common/menus/NavToolbarMenu';
import { menuEntries } from './AccessesMenu.entries';

const AccessesMenu: FunctionComponent = () => <NavToolbarMenu entries={menuEntries} />;

export default AccessesMenu;

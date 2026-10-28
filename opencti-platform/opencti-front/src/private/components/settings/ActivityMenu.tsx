import React, { FunctionComponent } from 'react';
import NavToolbarMenu from '../common/menus/NavToolbarMenu';
import { menuEntries } from './ActivityMenu.entries';

const ActivityMenu: FunctionComponent = () => <NavToolbarMenu entries={menuEntries} />;

export default ActivityMenu;

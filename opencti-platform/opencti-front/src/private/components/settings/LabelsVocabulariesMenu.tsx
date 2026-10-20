import React, { FunctionComponent } from 'react';
import NavToolbarMenu from '../common/menus/NavToolbarMenu';
import { menuEntries } from './LabelsVocabulariesMenu.entries';

const LabelsVocabulariesMenu: FunctionComponent = () => <NavToolbarMenu entries={menuEntries} />;

export default LabelsVocabulariesMenu;

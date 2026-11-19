/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import { createContext, useContext } from 'react';

// The editor shows a playbook in view mode (read it safely) or in edit mode (change it). The mode is
// a display mode, not a permission: the server keeps enforcing Manage Playbooks on every write.
export type PlaybookEditorMode = 'view' | 'edit';

// The mode a playbook opens in, decided once when the page mounts and never recomputed when the
// playbook is started or stopped: edit for a user who can manage playbooks on a stopped playbook,
// view otherwise. Nothing is stored: new, imported and duplicated playbooks are created stopped.
export const initialPlaybookMode = (canManage: boolean, running: boolean): PlaybookEditorMode => {
  return canManage && !running ? 'edit' : 'view';
};

// What the canvas offers in each mode. View mode keeps pan, zoom, the minimap, the layout direction
// and the last executions; it drops every control that changes the playbook.
export interface PlaybookCanvasAffordances {
  placeholders: boolean;
  edgeAddButton: boolean;
  nodeMenu: boolean;
  nodeOpensSettings: boolean;
  rewiring: boolean;
  history: boolean;
}

export const playbookCanvasAffordances = (canEdit: boolean): PlaybookCanvasAffordances => ({
  placeholders: canEdit,
  edgeAddButton: canEdit,
  nodeMenu: canEdit,
  nodeOpensSettings: canEdit,
  rewiring: canEdit,
  history: canEdit,
});

// canEdit = the user can manage playbooks and the editor is in edit mode, read by the cards and links.
export const PlaybookCanEditContext = createContext<boolean>(false);

export const usePlaybookCanvasAffordances = () => playbookCanvasAffordances(useContext(PlaybookCanEditContext));

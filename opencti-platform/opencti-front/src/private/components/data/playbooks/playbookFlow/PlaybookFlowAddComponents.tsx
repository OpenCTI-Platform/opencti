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

import { useEffect, useState } from 'react';
import { Edge } from 'reactflow';
import PlaybookFlowSelectComponent from './PlaybookFlowSelectComponent';
import Drawer from '../../../common/drawer/Drawer';
import { useFormatter } from '../../../../../components/i18n';
import { isEmptyField, isNotEmptyField } from '../../../../../utils/utils';
import PlaybookFlowForm from './PlaybookFlowForm';
import { PlaybookComponents, PlaybookNode } from '../types/playbook-types';

interface PlaybookFlowAddComponentsProps {
  action: string | null
  selectedNode: PlaybookNode | null
  selectedEdge: Edge | null
  setSelectedNode: (node: null) => void // null as type because useManipulateComponents is in JS
  setSelectedEdge: (node: null) => void // null as type because useManipulateComponents is in JS
  playbookComponents: PlaybookComponents
  onConfigAdd: (component: unknown, name: string, config: unknown) => void
  onConfigReplace: (component: unknown, name: string, config: unknown) => void
}

const PlaybookFlowAddComponents = ({
  action,
  setSelectedNode,
  setSelectedEdge,
  selectedNode,
  selectedEdge,
  playbookComponents,
  onConfigAdd,
  onConfigReplace,
}: PlaybookFlowAddComponentsProps) => {
  const { t_i18n } = useFormatter();
  const [componentId, setComponentId] = useState<string | null>(null);

  useEffect(() => {
    if (action === 'config' && selectedNode?.data?.component) {
      setComponentId(selectedNode?.data?.component?.id)
    }
  }, [selectedNode, action])

  const handleClose = () => {
    setSelectedNode(null);
    setSelectedEdge(null);
    setComponentId(null);
  };

  const isActionValid = action === 'config' || action === 'add' || action === 'replace';
  const hasSelection = selectedNode !== null || selectedEdge !== null
  const open = isActionValid && hasSelection;

  return (
    <Drawer
      open={open}
      title={t_i18n('Add components')}
      onClose={handleClose}
    >
      {({ onClose }) => (
        <>
          {(selectedNode || selectedEdge) && (
            <>
              {isEmptyField(componentId) && (
                <PlaybookFlowSelectComponent
                  components={playbookComponents}
                  onSelect={setComponentId}
                  selectedNode={selectedNode}
                />
              )}
              {isNotEmptyField(componentId) && (
                <PlaybookFlowForm
                  action={action}
                  componentId={componentId}
                  selectedNode={selectedNode}
                  playbookComponents={playbookComponents}
                  onConfigAdd={onConfigAdd}
                  onConfigReplace={onConfigReplace}
                  handleClose={onClose}
                />
              )}
            </>
          )}
        </>
      )}
    </Drawer>
  );
};

export default PlaybookFlowAddComponents;

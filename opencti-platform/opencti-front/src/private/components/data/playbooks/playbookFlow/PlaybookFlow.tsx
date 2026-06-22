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

import { useEffect } from 'react';
import ReactFlow from 'reactflow';
import { graphql, useFragment, useRefetchableFragment } from 'react-relay';
import PlaybookFlowAddComponents from './PlaybookFlowAddComponents';
import PlaybookFlowDeleteNode from './PlaybookFlowDeleteNode';
import useManipulateComponents from '../hooks/useManipulateComponents';
import { addPlaceholders, computeEdges, computeNodes } from '../utils/playbook';
import useLayout from '../hooks/useLayout';
import nodeTypes from '../types/nodes';
import edgeTypes from '../types/edges';
import { PlaybookFlow_playbookComponents$key } from './__generated__/PlaybookFlow_playbookComponents.graphql';
import { PlaybookFlow_playbook$key } from './__generated__/PlaybookFlow_playbook.graphql';

const defaultViewport = { x: 0, y: 0, zoom: 1.5 };
const proOptions = { account: 'paid-pro', hideAttribution: true };
const fitViewOptions = { padding: 0.8 };

const playbookFragment = graphql`
  fragment PlaybookFlow_playbook on Playbook {
    id
    playbook_definition
  }
`;

const playbookComponentsFragment = graphql`
  fragment PlaybookFlow_playbookComponents on Query
  @refetchable(queryName: "PlaybookFlowComponentsRefetchQuery") {
    playbookComponents {
      id
      name
      description
      icon
      category
      is_entry_point
      is_internal
      configuration_schema
      ports {
        id
        type
      }
    }
  }
`;

interface PlaybookFlowProps {
  dataPlaybook: PlaybookFlow_playbook$key;
  dataPlaybookComponents: PlaybookFlow_playbookComponents$key;
}

const PlaybookFlow = ({ dataPlaybookComponents, dataPlaybook }: PlaybookFlowProps) => {
  const playbook = useFragment(playbookFragment, dataPlaybook);
  const [{ playbookComponents }, refetchComponents] = useRefetchableFragment(
    playbookComponentsFragment,
    dataPlaybookComponents,
  );
  const definition = JSON.parse(playbook.playbook_definition || '{}');

  const {
    action,
    setAction,
    selectedNode,
    setSelectedNode,
    selectedEdge,
    setSelectedEdge,
    onConfigAdd,
    onConfigReplace,
    deleteNode,
  } = useManipulateComponents(playbook);

  // Some components (the XTM One AI agent nodes) expose a dynamic agent
  // picker whose options are resolved live from the XTM One intent catalog
  // when the `playbookComponents` query executes. That query is preloaded
  // once when the playbook opens, so an agent bound to an intent afterwards
  // would only show up after a full page reload. Refetch the component
  // catalog whenever the add / replace / configure drawer opens so newly
  // bound agents appear without reloading.
  const isComponentDrawerOpen = (action === 'add' || action === 'replace' || action === 'config')
    && (selectedNode !== null || selectedEdge !== null);
  useEffect(() => {
    if (isComponentDrawerOpen) {
      refetchComponents({}, { fetchPolicy: 'store-and-network' });
    }
  }, [isComponentDrawerOpen, refetchComponents]);

  const initialNodes = computeNodes(
    definition.nodes ?? [],
    playbookComponents,
    setAction as React.Dispatch<React.SetStateAction<string | null>>, // TODO : remove set casts when useManipulateComponents is in ts
    setSelectedNode as React.Dispatch<React.SetStateAction<string | null>>,
  );
  const initialEdges = computeEdges(
    definition.links ?? [],
    setAction as React.Dispatch<React.SetStateAction<string | null>>,
    setSelectedEdge as React.Dispatch<React.SetStateAction<string | null>>,
  );
  const { nodes: flowNodes, edges: flowEdges } = addPlaceholders(
    initialNodes,
    initialEdges,
    setAction as React.Dispatch<React.SetStateAction<string | null>>,
    setSelectedNode as React.Dispatch<React.SetStateAction<string | null>>,
  );

  // Needs to be called after computing nodes and edges.
  useLayout(playbook.id);

  return (
    <div style={{ width: '100%', height: '100%', margin: 0, overflow: 'hidden' }}>
      <ReactFlow
        defaultNodes={flowNodes}
        defaultEdges={flowEdges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        defaultViewport={defaultViewport}
        minZoom={0.2}
        fitView={true}
        fitViewOptions={fitViewOptions}
        nodesDraggable={false}
        nodesConnectable={false}
        zoomOnDoubleClick={false}
        proOptions={proOptions}
      />
      <PlaybookFlowAddComponents
        action={action}
        setSelectedNode={setSelectedNode}
        setSelectedEdge={setSelectedEdge}
        selectedNode={selectedNode}
        selectedEdge={selectedEdge}
        onConfigAdd={onConfigAdd}
        onConfigReplace={onConfigReplace}
        playbookComponents={playbookComponents}
      />
      <PlaybookFlowDeleteNode
        action={action}
        setAction={setAction}
        selectedNode={selectedNode}
        setSelectedNode={setSelectedNode}
        deleteNode={deleteNode}
      />
    </div>
  );
};

export default PlaybookFlow;

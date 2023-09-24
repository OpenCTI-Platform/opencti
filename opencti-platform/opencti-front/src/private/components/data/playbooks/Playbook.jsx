/*
Copyright (c) 2021-2023 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React, { useState } from 'react';
import { graphql, createFragmentContainer } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import 'reactflow/dist/style.css';
import ReactFlow, { ReactFlowProvider, useReactFlow } from 'reactflow';
import { v4 as uuid } from 'uuid';
import PlaybookHeader from './PlaybookHeader';
import useLayout from './hooks/useLayout';
import nodeTypes from './types/nodes';
import edgeTypes from './types/edges';
import PlaybookAddComponents from './PlaybookAddComponents';
import { addPlaceholders, computeNodes, computeEdges } from './utils/playbook';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    overflow: 'hidden',
  },
}));

const defaultViewport = { x: 0, y: 0, zoom: 1.5 };
const proOptions = { account: 'paid-pro', hideAttribution: true };

const PlaybookComponent = ({ playbook, playbookComponents }) => {
  const classes = useStyles();
  const definition = JSON.parse(playbook.playbook_definition);
  const [selectedNode, setSelectedNode] = useState(null);
  const width = window.innerWidth - 80;
  const height = window.innerHeight - 160;
  const Flow = () => {
    useLayout();
    const { setNodes, setEdges } = useReactFlow();
    const initialNodes = computeNodes(definition.nodes, playbookComponents);
    const initialEdges = computeEdges(definition.links);
    const { nodes: flowNodes, edges: flowEdges } = addPlaceholders(
      initialNodes,
      initialEdges,
    );
    const onConfig = (component, config) => {
      console.log(component, config);

      // This is a new node
      if (selectedNode.type === 'placeholder') {
        const childPlaceholderId = uuid();
        const childPlaceholderNode = {
          id: childPlaceholderId,
          position: { x: selectedNode.position.x, y: selectedNode.position.y },
          type: 'placeholder',
          data: {
            id: 'PLACEHOLDER',
            name: '+',
          },
        };
        const childPlaceholderEdge = {
          id: `${selectedNode.id}=>${childPlaceholderId}`,
          source: selectedNode.id,
          target: childPlaceholderId,
          type: 'placeholder',
        };
        setNodes((nodes) => nodes
          .map((node) => {
            if (node.id === selectedNode.id) {
              return {
                ...node,
                type: 'workflow',
                data: {
                  is_entry_point: node.data.is_entry_point,
                  id: component.id + uuid(),
                  name: component.name,
                  component_id: component.id,
                },
              };
            }
            return node;
          })
        // add the new placeholder node
          .concat([childPlaceholderNode]));
        setEdges((edges) => edges
          .map((edge) => {
            // here we are changing the type of the connecting edge from placeholder to workflow
            if (edge.target === selectedNode) {
              return {
                ...edge,
                type: 'workflow',
              };
            }
            return edge;
          })
        // add the new placeholder edge
          .concat([childPlaceholderEdge]));
      }
    };
    return (
      <>
        <ReactFlow
          defaultNodes={flowNodes}
          defaultEdges={flowEdges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          onNodeClick={(_, node) => setSelectedNode(node)}
          defaultViewport={defaultViewport}
          minZoom={0.2}
          maxZoom={4}
          fitView={true}
          nodesDraggable={false}
          nodesConnectable={false}
          zoomOnDoubleClick={false}
          proOptions={proOptions}
        />
        <PlaybookAddComponents
          open={selectedNode !== null}
          handleClose={() => setSelectedNode(null)}
          selectedNode={selectedNode}
          onConfig={onConfig}
          playbookComponents={playbookComponents}
        />
      </>
    );
  };
  return (
    <>
      <PlaybookHeader playbook={playbook} />
      <div className={classes.container} style={{ width, height }}>
        <ReactFlowProvider>
          <Flow />
        </ReactFlowProvider>
      </div>
    </>
  );
};

const Playbook = createFragmentContainer(PlaybookComponent, {
  playbook: graphql`
    fragment Playbook_playbook on Playbook {
      id
      entity_type
      name
      description
      playbook_definition
      playbook_running
    }
  `,
});

export default Playbook;

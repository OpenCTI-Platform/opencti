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
import { ErrorBoundary, SimpleError } from '@components/Error';
import PlaybookHeader from './PlaybookHeader';
import useLayout from './hooks/useLayout';
import nodeTypes from './types/nodes';
import edgeTypes from './types/edges';
import PlaybookAddComponents from './PlaybookAddComponents';
import {
  addPlaceholders,
  computeNodes,
  computeEdges,
  addNode,
} from './utils/playbook';
import { commitMutation } from '../../../../relay/environment';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    overflow: 'hidden',
  },
}));

const defaultViewport = { x: 0, y: 0, zoom: 1.5 };
const proOptions = { account: 'paid-pro', hideAttribution: true };
const fitViewOptions = { padding: 0.95 };

export const playbookAddNodeMutation = graphql`
  mutation PlaybookAddNodeMutation($input: PlaybookAddNodeInput!) {
    playbookAddNode(input: $input) {
      id
    }
  }
`;

export const playbookAddLinkMutation = graphql`
  mutation PlaybookAddLinkMutation($input: PlaybookAddLinkInput!) {
    playbookAddLink(input: $input) {
      id
    }
  }
`;

export const playbookDeleteNodeMutation = graphql`
  mutation PlaybookDeleteNodeMutation($id: ID!, $nodeId: ID!) {
    playbookDeleteNode(id: $id, nodeId: $nodeId) {
      id
    }
  }
`;

export const playbookDeleteLinkMutation = graphql`
  mutation PlaybookDeleteLinkMutation($id: ID!, $linkId: ID!) {
    playbookDeleteLink(id: $id, linkId: $linkId) {
      id
    }
  }
`;

const PlaybookComponent = ({ playbook, playbookComponents }) => {
  const classes = useStyles();
  const definition = JSON.parse(playbook.playbook_definition);
  const [selectedNode, setSelectedNode] = useState(null);
  const width = window.innerWidth - 80;
  const height = window.innerHeight - 160;
  const Flow = () => {
    useLayout();
    const { getNodes, setNodes, getEdges, setEdges } = useReactFlow();
    const initialNodes = computeNodes(definition.nodes, playbookComponents);
    const initialEdges = computeEdges(definition.links);
    const add = (originId) => {
      const originNode = getNodes()
        .filter((n) => n.id === originId)
        .at(0);
      setSelectedNode(originNode);
    };
    const { nodes: flowNodes, edges: flowEdges } = addPlaceholders(
      initialNodes,
      initialEdges,
      add,
    );
    const onConfig = (component, config) => {
      const position = {
        x: selectedNode.position.x,
        y: selectedNode.position.y,
      };
      commitMutation({
        mutation: playbookAddNodeMutation,
        variables: {
          input: {
            playbook_id: playbook.id,
            name: config?.name ?? component.name,
            component_id: component.id,
            position,
            configuration: config ? JSON.stringify(config) : null,
          },
        },
        onCompleted: () => {
          const parentNode = selectedNode.type === 'placeholder'
            ? selectedNode
            : getNodes()
              .filter(
                (n) => n.id
                      === getEdges()
                        .filter((o) => o.target === selectedNode.id)
                        .at(0).target,
              )
              .at(0);
          console.log(parentNode);
          commitMutation({
            mutation: playbookAddLinkMutation,
            variables: {
              input: {
                playbook_id: playbook.id,
                component_id: component.id,
                position,
                configuration: config ? JSON.stringify(config) : null,
              },
            },
            onCompleted: () => {
              const { nodes: newNodes, edges: newEdges } = addNode(
                selectedNode,
                add,
                component,
                config,
                getNodes(),
                getEdges(),
              );
              setNodes(newNodes);
              setEdges(newEdges);
            },
          });
        },
      });
    };
    return (
      <>
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
      <ErrorBoundary
        display={
          <div style={{ paddingTop: 28 }}>
            <SimpleError />
          </div>
        }
      >
        <div className={classes.container} style={{ width, height }}>
          <ReactFlowProvider>
            <Flow />
          </ReactFlowProvider>
        </div>
      </ErrorBoundary>
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

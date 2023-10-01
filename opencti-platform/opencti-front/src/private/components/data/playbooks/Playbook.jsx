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

import React from 'react';
import { graphql, createFragmentContainer } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import 'reactflow/dist/style.css';
import ReactFlow, { ReactFlowProvider } from 'reactflow';
import { ErrorBoundary, SimpleError } from '../../Error';
import PlaybookHeader from './PlaybookHeader';
import useLayout from './hooks/useLayout';
import nodeTypes from './types/nodes';
import edgeTypes from './types/edges';
import { addPlaceholders, computeNodes, computeEdges } from './utils/playbook';
import useManipulateComponents from './hooks/useManipulateComponents';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    overflow: 'hidden',
  },
}));

const defaultViewport = { x: 0, y: 0, zoom: 1.5 };
const proOptions = { account: 'paid-pro', hideAttribution: true };
const fitViewOptions = { padding: 0.8 };

const PlaybookComponent = ({ playbook, playbookComponents }) => {
  const classes = useStyles();
  const definition = JSON.parse(playbook.playbook_definition);
  const width = window.innerWidth - 80;
  const height = window.innerHeight - 160;
  const Flow = () => {
    const {
      setAction,
      setSelectedNode,
      setSelectedEdge,
      renderManipulateComponents,
    } = useManipulateComponents(playbook, playbookComponents);
    const initialNodes = computeNodes(
      definition.nodes,
      playbookComponents,
      setAction,
      setSelectedNode,
    );
    const initialEdges = computeEdges(
      definition.links,
      setAction,
      setSelectedEdge,
    );
    const { nodes: flowNodes, edges: flowEdges } = addPlaceholders(
      initialNodes,
      initialEdges,
      setAction,
      setSelectedNode,
    );
    useLayout(playbook.id);
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
        {renderManipulateComponents()}
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

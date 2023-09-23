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
import ReactFlow, { useNodesState, useEdgesState } from 'reactflow';
import { useFormatter } from '../../../../components/i18n';
import PlaybookHeader from './PlaybookHeader';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    overflow: 'hidden',
  },
}));

const initialNodes = [
  { id: '1', data: { label: 'Node 1' }, position: { x: '50%', y: 100 } },
  { id: '2', data: { label: 'Node 2' }, position: { x: 100, y: 200 } },
];
const initialEdges = [{ id: 'e1-2', source: '1', target: '2' }];

const defaultViewport = { x: 0, y: 0, zoom: 1.5 };

const PlaybookComponent = ({ playbook }) => {
  const classes = useStyles();
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  const { t } = useFormatter();
  const width = window.innerWidth - 80;
  const height = window.innerHeight - 160;
  return (
    <>
      <PlaybookHeader playbook={playbook} />
      <div className={classes.container} style={{ width, height }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          defaultViewport={defaultViewport}
          minZoom={0.2}
          maxZoom={4}
          proOptions={{ hideAttribution: true }}
        />
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

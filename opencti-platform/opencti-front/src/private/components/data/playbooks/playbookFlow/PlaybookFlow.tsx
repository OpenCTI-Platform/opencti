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

import { type ReactNode, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import ReactFlow, { Background, BackgroundVariant, MiniMap, useReactFlow } from 'reactflow';
import { useTheme } from '@mui/material/styles';
import { Alert } from '@filigran/design-system';
import { graphql, useFragment, useRefetchableFragment } from 'react-relay';
import PlaybookFlowAddComponents from './PlaybookFlowAddComponents';
import PlaybookFlowDeleteNode from './PlaybookFlowDeleteNode';
import useManipulateComponents from '../hooks/useManipulateComponents';
import { addPlaceholders, computeEdges, computeNodes } from '../utils/playbook';
import useLayout from '../hooks/useLayout';
import usePlaybookEdgeNames from '../hooks/usePlaybookEdgeNames';
import usePlaybookRewiring from '../hooks/usePlaybookRewiring';
import usePlaybookHistory, { type PlaybookHistoryControls } from '../hooks/usePlaybookHistory';
import { canvasSnapshot, type PlaybookOperation, type PlaybookOperationResult, type PlaybookSnapshot } from '../utils/playbookHistory';
import { PlaybookCanEditContext } from '../hooks/usePlaybookEditMode';
import { useFormatter } from '../../../../../components/i18n';
import { type PlaybookLayoutDirection, PlaybookLayoutDirectionContext, usePlaybookLayoutMode } from '../hooks/usePlaybookLayoutMode';
import PlaybookFlowToolbar from './PlaybookFlowToolbar';
import playbookFlowKeyboardProps from './playbookFlowKeyboard';
import { categoryAccent, PLAYBOOK_ARROW_ID } from '../types/nodes/playbookNodeGeometry';
import { PlaybookLastExecutionContext } from '../hooks/usePlaybookLastExecution';
import { lastExecutionByNode, type PlaybookNodeLastExecution } from '../utils/playbookLastExecution';
import type { Theme } from '../../../../../components/Theme';
import nodeTypes from '../types/nodes';
import edgeTypes from '../types/edges';
import { PlaybookFlow_playbookComponents$key } from './__generated__/PlaybookFlow_playbookComponents.graphql';
import { PlaybookFlow_playbook$key } from './__generated__/PlaybookFlow_playbook.graphql';

const defaultViewport = { x: 0, y: 0, zoom: 1.5 };
const proOptions = { account: 'paid-pro', hideAttribution: true };
// The first frame is a fit; useLayout then sets the landing view (a readable zoom on the entry point
// when the fit would make the cards unreadable).
const fitViewOptions = { padding: 0.2, maxZoom: 1 };
// The smallest canvas height, for a window too short to hold the header and a usable canvas.
const MIN_CANVAS_HEIGHT = 320;

// The canvas takes the height left under the page header, down to the bottom padding of the page,
// so the page never scrolls and the minimap and the bottom of the canvas stay on screen.
const useCanvasHeight = (bottomPadding: number) => {
  const ref = useRef<HTMLDivElement>(null);
  const [height, setHeight] = useState<number | null>(null);
  useLayoutEffect(() => {
    const measure = () => {
      if (!ref.current) return;
      const top = ref.current.getBoundingClientRect().top + window.scrollY;
      setHeight(Math.max(MIN_CANVAS_HEIGHT, Math.floor(window.innerHeight - top - bottomPadding)));
    };
    measure();
    window.addEventListener('resize', measure);
    return () => window.removeEventListener('resize', measure);
  }, [bottomPadding]);
  return { ref, height };
};

const playbookFragment = graphql`
  fragment PlaybookFlow_playbook on Playbook {
    id
    playbook_definition
    last_executions {
      id
      execution_start
      steps {
        id
        status
        duration
      }
    }
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

// What the node cards read from the canvas: the layout direction, the latest outcome of each step
// and whether the playbook can be changed (edit mode).
const PlaybookCanvasContexts = ({ direction, lastExecutions, canEdit, children }: {
  direction: PlaybookLayoutDirection;
  lastExecutions: Map<string, PlaybookNodeLastExecution>;
  canEdit: boolean;
  children: ReactNode;
}) => (
  <PlaybookLayoutDirectionContext.Provider value={direction}>
    <PlaybookCanEditContext.Provider value={canEdit}>
      <PlaybookLastExecutionContext.Provider value={lastExecutions}>
        {children}
      </PlaybookLastExecutionContext.Provider>
    </PlaybookCanEditContext.Provider>
  </PlaybookLayoutDirectionContext.Provider>
);

interface PlaybookFlowProps {
  dataPlaybook: PlaybookFlow_playbook$key;
  dataPlaybookComponents: PlaybookFlow_playbookComponents$key;
  // The user can manage playbooks and the editor is in edit mode (Playbook.tsx).
  canEdit: boolean;
  running: boolean;
}

const PlaybookFlow = ({ dataPlaybookComponents, dataPlaybook, canEdit, running }: PlaybookFlowProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const canvas = useCanvasHeight(Number.parseInt(theme.spacing(3), 10) || 24);
  const playbook = useFragment(playbookFragment, dataPlaybook);
  const { direction, setDirection } = usePlaybookLayoutMode(playbook.id);
  const [{ playbookComponents }, refetchComponents] = useRefetchableFragment(
    playbookComponentsFragment,
    dataPlaybookComponents,
  );
  const definition = JSON.parse(playbook.playbook_definition || '{}');
  // The outcome of each step in its latest execution, shown as a badge on its card.
  const lastExecutions = useMemo(() => lastExecutionByNode(playbook.last_executions), [playbook.last_executions]);

  // The session history is created after the selection state it clears, so the changes reach it
  // through this stable recorder.
  const { getNodes, getEdges } = useReactFlow();
  const historyRef = useRef<PlaybookHistoryControls | null>(null);
  // The focusable wrapper of the flow: the single-key canvas shortcuts answer only inside it.
  const canvasFocusRef = useRef<HTMLDivElement>(null);
  const historyRecorder = useMemo(() => ({
    snapshot: () => canvasSnapshot(getNodes(), getEdges()),
    record: (op: PlaybookOperation, before: PlaybookSnapshot, result?: PlaybookOperationResult) => historyRef.current?.record(op, before, result),
    reset: () => historyRef.current?.reset(),
  }), [getNodes, getEdges]);

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
  } = useManipulateComponents(playbook, historyRecorder);

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
    setAction,
    setSelectedNode,
    definition.links ?? [],
  );
  const initialEdges = computeEdges(
    definition.links ?? [],
    setAction,
    setSelectedEdge,
  );
  const { nodes: flowNodes, edges: flowEdges } = addPlaceholders(
    initialNodes,
    initialEdges,
    setAction,
    setSelectedNode,
  );

  // Needs to be called after computing nodes and edges.
  const { miniMapShown, onMoveStart } = useLayout(direction);
  // Every link is read by a screen reader as "Link from <step> to <step>", never by its ids.
  usePlaybookEdgeNames();

  // Back to view mode: an open drawer or dialog closes, nothing stays half-edited.
  useEffect(() => {
    if (!canEdit) {
      setAction(null);
      setSelectedNode(null);
      setSelectedEdge(null);
    }
  }, [canEdit, setAction, setSelectedNode, setSelectedEdge]);

  // Rewiring by drag: only in edit mode; view mode and users without Manage Playbooks get a read-only canvas.
  const { onConnect, onEdgeUpdate } = usePlaybookRewiring(
    playbook.id,
    setAction,
    setSelectedEdge,
    setSelectedNode,
    historyRecorder,
  );
  // Undo / redo of the session (Ctrl/Cmd+Z, Shift+Ctrl/Cmd+Z), through inverse operations.
  const history = usePlaybookHistory(
    playbook.id,
    playbookComponents,
    setAction,
    setSelectedNode,
    setSelectedEdge,
  );
  useEffect(() => {
    historyRef.current = history;
  }, [history]);

  return (
    <PlaybookCanvasContexts direction={direction} lastExecutions={lastExecutions} canEdit={canEdit}>
      <div
        ref={canvas.ref}
        style={{ position: 'relative', display: 'flex', flexDirection: 'column', width: '100%', height: canvas.height ?? '100%', margin: 0, overflow: 'hidden' }}
      >
        {canEdit && running && (
          // Inside the measured block, above the flow: the canvas gives up the notice's height, so the notice
          // never covers a step or the toolbar and the page never scrolls. The same 12 px above and below
          // keep it apart from the metadata line of the header.
          <div
            data-testid="playbook-running-notice"
            style={{ flex: 'none', display: 'flex', justifyContent: 'center', paddingTop: 12, paddingBottom: 12 }}
          >
            <Alert severity="warning" title={t_i18n('This playbook is running: your changes apply immediately.')} />
          </div>
        )}
        <svg style={{ position: 'absolute', width: 0, height: 0 }} aria-hidden="true">
          <defs>
            <marker
              id={PLAYBOOK_ARROW_ID}
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="8"
              markerHeight="8"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill={theme.palette.text?.secondary} />
            </marker>
          </defs>
        </svg>
        {/* Focusable so a click on the pane gives it the focus: F, V, H, +, - and ? answer here only. */}
        <div
          ref={canvasFocusRef}
          data-testid="playbook-canvas"
          role="region"
          // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
          tabIndex={0}
          aria-label={t_i18n('Playbook canvas')}
          style={{ position: 'relative', flex: 1, minHeight: 0 }}
        >
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
            {...playbookFlowKeyboardProps}
            nodesConnectable={canEdit}
            edgesUpdatable={canEdit}
            onConnect={canEdit ? onConnect : undefined}
            onEdgeUpdate={canEdit ? onEdgeUpdate : undefined}
            zoomOnDoubleClick={false}
            onMoveStart={onMoveStart}
            proOptions={proOptions}
          >
            <Background variant={BackgroundVariant.Dots} gap={20} size={1} color={theme.palette.divider} />
            {miniMapShown && (
              <MiniMap
                pannable
                zoomable
                ariaLabel={null}
                nodeColor={(node) => (node.type === 'placeholder' ? 'transparent' : categoryAccent(theme, node.data?.component?.category))}
                maskColor={theme.palette.action?.hover}
                style={{ backgroundColor: theme.palette.background.paper }}
              />
            )}
            <PlaybookFlowToolbar direction={direction} onDirectionChange={setDirection} history={canEdit ? history : undefined} canvasRef={canvasFocusRef} />
          </ReactFlow>
        </div>
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
    </PlaybookCanvasContexts>
  );
};

export default PlaybookFlow;

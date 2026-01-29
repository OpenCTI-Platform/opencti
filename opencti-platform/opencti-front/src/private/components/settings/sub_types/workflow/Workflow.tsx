import { useCallback, useEffect, useState } from 'react';
import ReactFlow, { Edge, EdgeMouseHandler, Node, NodeMouseHandler, Panel, useEdgesState, useNodesState, useReactFlow } from 'reactflow';
// @ts-expect-error ts-migrate(7016) FIXME: Could not find a declaration file for module 'reac... Remove this comment to see the full error message
import 'reactflow/dist/style.css';
import WorkflowEditionDrawer from './WorkflowEditionDrawer';
import useWorkflowLayout, { LayoutOptions, Direction } from './hooks/useWorkflowLayout';
import nodeTypes from './NodeTypes';
import edgeTypes from './EdgeTypes';
import Button from '@common/button/Button';
import { SaveOutlined } from '@mui/icons-material';
import { transformToWorkflowDefinition } from './utils';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { workflowQuery } from '../SubTypeWorkflow';
import { SubTypeWorkflowQuery } from '../__generated__/SubTypeWorkflowQuery.graphql';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../../../components/i18n';
import { WorkflowDefinitionMutation } from './__generated__/WorkflowDefinitionMutation.graphql';
import { useWorkflowInitialElements } from './hooks/useWorkflowInitialElements';
import { usePlaceholdersSync } from './hooks/usePlaceholdersSync';
import { useStatusConnection } from './hooks/useStatusConnection';

const workflowDefinitionSetMutation = graphql`
  mutation WorkflowDefinitionMutation($entityType: String!, $definition: String!) {
    workflowDefinitionSet(entityType: $entityType, definition: $definition) {
      id
    }
  }
`;

const defaultViewport = { x: 0, y: 0, zoom: 1.5 };
const proOptions = { account: 'paid-pro', hideAttribution: true };
const fitViewOptions = {};
// const defaultEdgeOptions = {
//   type: 'straight',
//   markerEnd: { type: MarkerType.Arrow },
//   style: { strokeWidth: 2, strokeDasharray: '3 3' },
// };

const Workflow = ({ queryRef }: { queryRef: PreloadedQuery<SubTypeWorkflowQuery> }) => {
  const { t_i18n } = useFormatter();
  const { fitView, getNode } = useReactFlow();

  const { workflowDefinition, statusTemplates, members } = usePreloadedQuery<SubTypeWorkflowQuery>(
    workflowQuery,
    queryRef,
  );

  // 1. Get initial edges and nodes from workflow definition
  const { initialNodes, initialEdges } = useWorkflowInitialElements(workflowDefinition, statusTemplates, members);

  const [nodes, _dispatchNodes, onNodesChange] = useNodesState<Node[]>(initialNodes);
  const [edges, _dispatchEdges, onEdgesChange] = useEdgesState<Edge[]>(initialEdges);
  // 2. Sync Placeholders (The effect is now tucked away)
  usePlaceholdersSync(nodes, edges);

  const layoutOptions: LayoutOptions = {
    direction: 'TB' as Direction,
    spacing: [50, 50],
  };

  // 3. Sync layout and recenter graph
  useWorkflowLayout(layoutOptions);

  useEffect(() => {
    console.log({ nodes, edges });
    fitView();
  }, [nodes, edges, fitView]);

  // Update workflow definition
  const [saveWorkflowDefinition] = useApiMutation<WorkflowDefinitionMutation>(
    workflowDefinitionSetMutation,
    undefined,
    { successMessage: t_i18n('Workflow successfully updated') },
  );

  const onSave = () => {
    const finalSchema = transformToWorkflowDefinition(nodes, edges, workflowDefinition);
    // TODO remove log
    console.log('Saved Schema:', JSON.stringify(finalSchema, null, 2));
    saveWorkflowDefinition({
      variables: { entityType: 'DraftWorkspace', definition: JSON.stringify(finalSchema) },
    });
  };

  // Edit status and trantions
  const [selectedElement, setSelectedElement] = useState<Node | Edge | null>(null);
  const onNodeClick: NodeMouseHandler = useCallback(
    (_, node) => {
      getNode(node.id);
      // On placeholder click we need to give the parent status
      if (node.type === 'placeholder') {
        setSelectedElement({ ...node, source: node.id.replace('placeholder-', '') });
      } else {
        setSelectedElement(node);
      }
    },
    [getNode],
  );

  const onEdgeClick: EdgeMouseHandler = useCallback(
    (_event, edge) => {
      const newState = {
        id: edge.id,
        type: 'placeholder',
        data: { name: null, conditions: [] },
        position: { x: 0, y: 0 },
        source: edge.source,
        target: edge.target,
      };
      setSelectedElement(newState);
    },
    [],
  );

  const onConnect = useStatusConnection();

  return (
    <div style={{ width: '100%', height: '100%', margin: 0, overflow: 'hidden' }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onConnect={onConnect}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        onNodeClick={onNodeClick}
        onEdgeClick={onEdgeClick}
        fitView
        defaultViewport={defaultViewport}
        minZoom={0.2}
        fitViewOptions={fitViewOptions}
        nodesDraggable={false}
        zoomOnDoubleClick={false}
        proOptions={proOptions}
      >
        <Panel position="top-right" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <Button onClick={onSave} startIcon={<SaveOutlined />} variant="secondary">
            Save
          </Button>
          <Button onClick={() => setSelectedElement({ id: 'new-status', type: 'placeholder', data: {}, position: { x: 0, y: 0 } })}>
            Add Status
          </Button>
        </Panel>
      </ReactFlow>
      <WorkflowEditionDrawer selectedElement={selectedElement} onClose={() => setSelectedElement(null)} />
    </div>
  );
};
export default Workflow;

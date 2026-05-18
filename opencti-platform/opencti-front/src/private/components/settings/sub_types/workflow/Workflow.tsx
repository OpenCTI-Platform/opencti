import { useCallback, useEffect, useRef, useState } from 'react';
import ReactFlow, { Edge, EdgeMouseHandler, Node, NodeMouseHandler, Panel, useEdgesState, useNodesState, useReactFlow } from 'reactflow';
import 'reactflow/dist/style.css';
import WorkflowEditionDrawer from './WorkflowEditionDrawer';
import useWorkflowLayout, { LayoutOptions, Direction } from './hooks/useWorkflowLayout';
import nodeTypes from './NodeTypes';
import edgeTypes from './EdgeTypes';
import Button from '@common/button/Button';
import { Typography } from '@mui/material';
import { NEW_STATUS_NAME, transformToWorkflowDefinition, WorkflowNodeType } from './utils';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { workflowQuery } from '../SubTypeWorkflow';
import { SubTypeWorkflowQuery } from '../__generated__/SubTypeWorkflowQuery.graphql';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../../../components/i18n';
import { WorkflowDefinitionMutation } from './__generated__/WorkflowDefinitionMutation.graphql';
import { useWorkflowInitialElements } from './hooks/useWorkflowInitialElements';
import { usePlaceholdersSync } from './hooks/usePlaceholdersSync';
import { useStatusConnection } from './hooks/useStatusConnection';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../../../../components/Theme';
import PublishButton from './PublishButton';

export interface WorkflowValidationError {
  type: string;
  message: string;
  path?: Array<{ id: string; entity_type: string }>;
}

const workflowDefinitionSetMutation = graphql`
  mutation WorkflowDefinitionMutation($entityType: String!, $definition: String!) {
    workflowDefinitionSet(entityType: $entityType, definition: $definition) {
      id
      errors {
        type
        message
        path {
          id
          entity_type
        }
      }
    }
  }
`;

const defaultViewport = { x: 0, y: 0, zoom: 1.5 };
const proOptions = { account: 'paid-pro', hideAttribution: true };
const fitViewOptions = {};

const emptyElement = {
  id: NEW_STATUS_NAME,
  type: WorkflowNodeType.placeholder,
  data: {},
  position: { x: 0, y: 0 },
};

const Workflow = ({ queryRef }: { queryRef: PreloadedQuery<SubTypeWorkflowQuery> }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { fitView, getNode } = useReactFlow();

  const { workflowDefinition, statusTemplates, members } = usePreloadedQuery<SubTypeWorkflowQuery>(
    workflowQuery,
    queryRef,
  );

  // 1. Get initial edges and nodes from workflow definition
  const { initialNodes, initialEdges } = useWorkflowInitialElements(workflowDefinition, statusTemplates, members);

  const [nodes, _dispatchNodes, onNodesChange] = useNodesState<Node>(initialNodes);
  const [edges, _dispatchEdges, onEdgesChange] = useEdgesState<Edge>(initialEdges);
  // 2. Sync Placeholders (The effect is now tucked away)
  usePlaceholdersSync(nodes, edges);

  const layoutOptions: LayoutOptions = {
    direction: 'TB' as Direction,
    spacing: [50, 50],
  };

  // 3. Sync layout and recenter graph
  useWorkflowLayout(layoutOptions);

  useEffect(() => {
    fitView();
  }, [nodes, edges, fitView]);

  // Update workflow definition
  const [saveWorkflowDefinition] = useApiMutation<WorkflowDefinitionMutation>(workflowDefinitionSetMutation);

  const [workflowDefinitionStatus, setWorkflowDefinitionStatus] = useState<{
    published: boolean;
    validationErrors: WorkflowValidationError[];
  }>({ published: false, validationErrors: [] });

  // Store previous schema to avoid unnecessary mutations
  const previousSchemaRef = useRef<string | null>(null);

  useEffect(() => {
    const finalSchema = transformToWorkflowDefinition(nodes, edges, workflowDefinition);
    const schemaString = JSON.stringify(finalSchema);

    // Only save if schema has actually changed
    if (previousSchemaRef.current === schemaString) {
      return;
    }

    previousSchemaRef.current = schemaString;

    saveWorkflowDefinition({
      variables: { entityType: 'DraftWorkspace', definition: schemaString },
      onCompleted: (response) => {
        if (response.workflowDefinitionSet) {
          const { errors } = response.workflowDefinitionSet;
          if (errors && errors.length > 0) {
            const validationErrors = errors
              .filter((e) => e !== null && e !== undefined)
              .map((e) => ({
                type: e!.type,
                message: e!.message,
                path: e!.path?.map((p) => ({ id: p.id, entity_type: p.entity_type })),
              }));
            setWorkflowDefinitionStatus({
              published: false,
              validationErrors,
            });
          } else {
            setWorkflowDefinitionStatus({ published: true, validationErrors: [] });
          }
        }
      },
    });
  }, [nodes, edges]);

  // Edit status and trantions
  const [open, setOpen] = useState<boolean>(false);
  const [selectedElement, setSelectedElement] = useState<Node | Edge>(emptyElement);
  const onNodeClick: NodeMouseHandler = useCallback(
    (_, node) => {
      getNode(node.id);
      // On placeholder click we need to give the parent status
      if (node.type === WorkflowNodeType.placeholder) {
        setSelectedElement({ ...node, source: node.id.replace('placeholder-', '') });
      } else {
        setSelectedElement(node);
      }
      setOpen(true);
    },
    [getNode],
  );

  const onEdgeClick: EdgeMouseHandler = useCallback(
    (_event, edge) => {
      const newState = {
        id: edge.id,
        type: WorkflowNodeType.placeholder,
        data: { name: null, conditions: {} },
        position: { x: 0, y: 0 },
        source: edge.source,
        target: edge.target,
      };
      setSelectedElement(newState);
      setOpen(true);
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
        {nodes.length ? (
          <Panel position="top-right" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <PublishButton validationStatus={workflowDefinitionStatus} onPublish={() => {}} />
            <Button
              onClick={() => {
                setSelectedElement({
                  id: NEW_STATUS_NAME,
                  type: WorkflowNodeType.placeholder,
                  data: {},
                  position: { x: 0, y: 0 },
                });
                setOpen(true);
              }}
            >
              {t_i18n('Add Status')}
            </Button>
          </Panel>
        ) : (
          <Panel
            position="top-center"
            style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: 12,
              top: '40%',
            }}
          >
            <Typography variant="subtitle2" color={theme.palette.text.light}>
              {t_i18n('Start to define your workflow by adding a Status.')}
            </Typography>
            <Button
              onClick={() => {
                setSelectedElement({
                  id: NEW_STATUS_NAME,
                  type: WorkflowNodeType.placeholder,
                  data: {},
                  position: { x: 0, y: 0 },
                });
                setOpen(true);
              }}
            >
              {t_i18n('Add Status')}
            </Button>
          </Panel>
        )}
      </ReactFlow>
      <WorkflowEditionDrawer
        open={open}
        selectedElement={selectedElement}
        onClose={() => {
          setSelectedElement(emptyElement);
          setOpen(false);
        }}
      />
    </div>
  );
};
export default Workflow;

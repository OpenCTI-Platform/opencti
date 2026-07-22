import { useCallback, useEffect, useRef, useState } from 'react';
import ReactFlow, { Edge, EdgeMouseHandler, Node, NodeMouseHandler, Panel, useEdgesState, useNodesState, useReactFlow } from 'reactflow';
import 'reactflow/dist/style.css';
import WorkflowEditionDrawer from './WorkflowEditionDrawer';
import useWorkflowLayout, { LayoutOptions, Direction } from './hooks/useWorkflowLayout';
import nodeTypes from './NodeTypes';
import edgeTypes from './EdgeTypes';
import Button from '@common/button/Button';
import { Box, Typography } from '@mui/material';
import { NEW_STATUS_NAME, transformToWorkflowDefinition, WorkflowNodeType } from './utils';
import { graphql, PreloadedQuery, usePreloadedQuery, useMutation } from 'react-relay';
import { workflowDependenciesQuery, workflowQuery } from '../SubTypeWorkflow';
import { SubTypeWorkflowQuery, SubTypeWorkflowQuery$data } from '../__generated__/SubTypeWorkflowQuery.graphql';
import { SubTypeWorkflowDependenciesQuery } from '../__generated__/SubTypeWorkflowDependenciesQuery.graphql';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../../../components/i18n';
import { WorkflowDefinitionMutation } from './__generated__/WorkflowDefinitionMutation.graphql';
import { WorkflowPublishMutation } from './__generated__/WorkflowPublishMutation.graphql';
import { WorkflowRestorePublishedMutation } from './__generated__/WorkflowRestorePublishedMutation.graphql';
import { useWorkflowInitialElements, convertEdgesToObject } from './hooks/useWorkflowInitialElements';
import { usePlaceholdersSync } from './hooks/usePlaceholdersSync';
import { useStatusConnection } from './hooks/useStatusConnection';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../../../../components/Theme';
import PublishButton from './PublishButton';
import RestoreConfirmDialog from './RestoreConfirmDialog';
import { MESSAGING$ } from '../../../../../relay/environment';

export interface WorkflowValidationError {
  type: string;
  message: string;
  path?: Array<{ id: string; entity_type: string }> | null;
}

interface WorkflowValidationErrorsToastContentProps {
  errors: WorkflowValidationError[];
  t_i18n: (key: string) => string;
  statusTemplates?: SubTypeWorkflowQuery$data['statusTemplates'];
}

const WorkflowValidationErrorsToastContent = ({ errors, t_i18n, statusTemplates }: WorkflowValidationErrorsToastContentProps) => {
  const statusTemplateMap = convertEdgesToObject(statusTemplates);

  const groupedErrors = errors.reduce((acc, error) => {
    if (!acc[error.type]) acc[error.type] = [];
    acc[error.type].push(error);
    return acc;
  }, {} as Record<string, WorkflowValidationError[]>);

  return (
    <Box>
      <Typography variant="body2" sx={{ fontWeight: 'bold', mb: 0.5 }}>
        {t_i18n('Workflow validation errors')} ({errors.length})
      </Typography>
      {Object.entries(groupedErrors).map(([type, typeErrors]) => (
        <Box key={type} sx={{ mt: 0.5 }}>
          <Typography variant="caption" sx={{ fontWeight: 'bold', textTransform: 'capitalize' }}>
            {type.replace(/_/g, ' ')}
          </Typography>
          {typeErrors.map((error, index) => (
            <Typography key={index} variant="caption" component="div" sx={{ ml: 1 }}>
              • {error.message}
              {error.path && error.path.length > 0 && (
                <Typography variant="caption" component="span" sx={{ ml: 0.5, fontStyle: 'italic' }}>
                  ({error.path.map((ref) => {
                    if (ref.entity_type === 'StatusTemplate') {
                      return statusTemplateMap[ref.id]?.name ?? ref.id;
                    }
                    return `${ref.entity_type} ${ref.id}`;
                  }).join(', ')})
                </Typography>
              )}
            </Typography>
          ))}
        </Box>
      ))}
    </Box>
  );
};

const workflowDefinitionSetMutation = graphql`
  mutation WorkflowDefinitionMutation($entityType: String!, $definition: String!) {
    workflowDefinitionSet(entityType: $entityType, definition: $definition) {
      id
      published
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

const workflowDefinitionPublishMutation = graphql`
  mutation WorkflowPublishMutation($entityType: String!) {
    workflowDefinitionPublish(entityType: $entityType) {
      id
      workflow_id
      published
    }
  }
`;

const workflowDefinitionRestorePublishedMutation = graphql`
  mutation WorkflowRestorePublishedMutation($entityType: String!) {
    workflowDefinitionRestorePublished(entityType: $entityType) {
      id
      published
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

const Workflow = ({
  queryRef,
  depsQueryRef,
  onRefetch,
}: {
  queryRef: PreloadedQuery<SubTypeWorkflowQuery>;
  depsQueryRef: PreloadedQuery<SubTypeWorkflowDependenciesQuery>;
  onRefetch: () => void;
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { fitView, getNode } = useReactFlow();

  const { workflowDefinition, statusTemplates } = usePreloadedQuery<SubTypeWorkflowQuery>(
    workflowQuery,
    queryRef,
  );
  const { members } = usePreloadedQuery<SubTypeWorkflowDependenciesQuery>(
    workflowDependenciesQuery,
    depsQueryRef,
  );

  // 1. Get initial edges and nodes from workflow definition
  const { initialNodes, initialEdges } = useWorkflowInitialElements(workflowDefinition, statusTemplates, members);

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>(initialEdges);
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

  // Publish workflow definition
  const [commitPublish] = useMutation<WorkflowPublishMutation>(workflowDefinitionPublishMutation);

  // Restore published workflow definition
  const [restoreWorkflowDefinition] = useApiMutation<WorkflowRestorePublishedMutation>(
    workflowDefinitionRestorePublishedMutation,
  );

  const [workflowDefinitionStatus, setWorkflowDefinitionStatus] = useState<{
    hasUnpublishedChanges: boolean;
    hasPublishedVersion: boolean;
    validationErrors: WorkflowValidationError[];
  }>({
    hasUnpublishedChanges: !(workflowDefinition?.published ?? false),
    hasPublishedVersion: workflowDefinition?.hasPublishedVersion ?? false,
    validationErrors: workflowDefinition?.errors ? [...workflowDefinition.errors as WorkflowValidationError[]] : [],
  });

  // Store previous schema to avoid unnecessary mutations
  const previousSchemaRef = useRef<string | null>(null);

  // 4. When Relay delivers fresh data after a parent refetch (e.g., after restore),
  //    reset the React Flow state to reflect the new workflow definition.
  const isInitialMountRef = useRef(true);
  useEffect(() => {
    if (isInitialMountRef.current) {
      isInitialMountRef.current = false;
      return;
    }
    setNodes(initialNodes);
    setEdges(initialEdges);
    previousSchemaRef.current = JSON.stringify(
      transformToWorkflowDefinition(initialNodes, initialEdges, workflowDefinition),
    );
    // Sync publish status with the freshly fetched definition (e.g. after restore)
    setWorkflowDefinitionStatus({
      hasUnpublishedChanges: !(workflowDefinition?.published ?? false),
      hasPublishedVersion: workflowDefinition?.hasPublishedVersion ?? false,
      validationErrors: workflowDefinition?.errors
        ? [...workflowDefinition.errors as WorkflowValidationError[]]
        : [],
    });
  }, [initialNodes, initialEdges]);

  // Initialize the previous schema ref on mount to prevent initial mutation
  useEffect(() => {
    if (previousSchemaRef.current === null) {
      const initialSchema = transformToWorkflowDefinition(initialNodes, initialEdges, workflowDefinition);
      previousSchemaRef.current = JSON.stringify(initialSchema);
    }
  }, []);

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
            setWorkflowDefinitionStatus((prev) => ({ ...prev, hasUnpublishedChanges: true, validationErrors }));
          } else {
            // No errors, but stay in draft mode until explicitly published
            setWorkflowDefinitionStatus((prev) => ({ ...prev, hasUnpublishedChanges: true, validationErrors: [] }));
          }
        }
      },
    });
  }, [nodes, edges]);

  // Handle reset action — clears the draft to an empty schema without touching the published version
  const handleReset = () => {
    // Derive the schema from transformToWorkflowDefinition so that the payload and
    // the autosave guard are always aligned: the effect recomputes the same function
    // after setNodes([]) / setEdges([]) and will see an identical string, preventing
    // a spurious follow-up mutation.
    const emptySchemaString = JSON.stringify(transformToWorkflowDefinition([], [], workflowDefinition));
    previousSchemaRef.current = emptySchemaString;
    saveWorkflowDefinition({
      variables: { entityType: 'DraftWorkspace', definition: emptySchemaString },
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
            setWorkflowDefinitionStatus((prev) => ({ ...prev, hasUnpublishedChanges: true, validationErrors }));
          } else {
            setWorkflowDefinitionStatus((prev) => ({ ...prev, hasUnpublishedChanges: true, validationErrors: [] }));
          }
        }
        setNodes([]);
        setEdges([]);
      },
    });
  };

  // Handle publish action
  const handlePublish = () => {
    if (workflowDefinitionStatus.validationErrors.length > 0) {
      MESSAGING$.notifyError(
        <WorkflowValidationErrorsToastContent errors={workflowDefinitionStatus.validationErrors} t_i18n={t_i18n} />,
      );
      return;
    }
    commitPublish({
      variables: { entityType: 'DraftWorkspace' },
      onCompleted: () => {
        MESSAGING$.notifySuccess(t_i18n('Workflow successfully published'));
        setWorkflowDefinitionStatus({
          hasUnpublishedChanges: false,
          hasPublishedVersion: true,
          validationErrors: [],
        });
      },
      onError: (error) => {
        const firstError = (error as { res?: { errors?: Array<{ message?: string; extensions?: { data } }> } })?.res?.errors?.[0];
        const data = firstError?.extensions?.data as { removedStates?: string[]; entityType?: string } | undefined;
        const publishErrors: WorkflowValidationError[] = [{
          type: 'PUBLISH_ERROR',
          message: firstError?.message ?? t_i18n('An error occurred while publishing the workflow'),
          path: data?.removedStates?.map((s: string) => ({ id: s, entity_type: 'StatusTemplate' })) ?? [],
        }];
        MESSAGING$.notifyError(
          <WorkflowValidationErrorsToastContent errors={publishErrors} t_i18n={t_i18n} statusTemplates={statusTemplates} />,
        );
      },
    });
  };

  // Handle restore action — reloads the published version into the draft
  const handleRestore = () => {
    restoreWorkflowDefinition({
      variables: { entityType: 'DraftWorkspace' },
      onCompleted: () => {
        // Directly reset local state to `initialNodes`/`initialEdges`.
        // The Relay store already holds the published states (only full queries update
        // `states`/`transitions`; mutation responses don't). So after deletion of all
        // nodes the store is unchanged → the sync useEffect won't fire on a refetch
        // that returns identical data. Calling setNodes here is the reliable path.
        setNodes(initialNodes);
        setEdges(initialEdges);
        previousSchemaRef.current = JSON.stringify(
          transformToWorkflowDefinition(initialNodes, initialEdges, workflowDefinition),
        );
        setWorkflowDefinitionStatus({ hasUnpublishedChanges: false, hasPublishedVersion: true, validationErrors: [] });
        // Also refetch in case the store is stale (e.g. published version changed
        // after the initial page load). The sync useEffect handles that case.
        onRefetch();
      },
    });
  };

  // Edit status and transitions
  const [open, setOpen] = useState<boolean>(false);
  const [emptyStateRestoreConfirmOpen, setEmptyStateRestoreConfirmOpen] = useState(false);
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
            <PublishButton
              validationStatus={workflowDefinitionStatus}
              onPublish={handlePublish}
              onReset={handleReset}
              onRestore={handleRestore}
              hasPublishedVersion={workflowDefinitionStatus.hasPublishedVersion}
            />
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
            <Button
              variant="secondary"
              onClick={() => setEmptyStateRestoreConfirmOpen(true)}
              disabled={!workflowDefinitionStatus.hasPublishedVersion || !workflowDefinitionStatus.hasUnpublishedChanges}
            >
              {t_i18n('Restore published version')}
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
      <RestoreConfirmDialog
        open={emptyStateRestoreConfirmOpen}
        onClose={() => setEmptyStateRestoreConfirmOpen(false)}
        onConfirm={() => {
          setEmptyStateRestoreConfirmOpen(false);
          handleRestore();
        }}
      />
    </div>
  );
};
export default Workflow;

import { useMemo } from 'react';
import { Node, Edge, useReactFlow } from 'reactflow';
import * as Yup from 'yup';
import { useFormatter } from '../../../../../../components/i18n';
import useAddStatus from './useAddStatus';
import useDeleteElement from './useDeleteElement';
import { WorkflowEditionFormValues } from '../WorkflowEditionDrawer';
import { withoutDefaultShareRequestedEntities, WorkflowActionType, WorkflowNodeType } from '../utils';

// Validation Factory
const getValidationSchema = (isStatus: boolean, t: (s: string) => string) => {
  if (isStatus) {
    return Yup.object().shape({
      statusTemplate: Yup.object().required(t('This field is required')),
      // The backend refuses a share action without organization.
      onEnter: Yup.array().of(Yup.object().shape({
        params: Yup.object().when('type', {
          is: WorkflowActionType.shareRequestedEntities,
          then: (schema) => schema.shape({ organizations: Yup.array().min(1, t('This field is required')) }),
        }),
      })),
    });
  }
  return Yup.object().shape({
    event: Yup.string().required(t('This field is required')),
  });
};

// An outcome marks one state: setting it on a state takes it off the state that held it, along with
// the share action Approved added by default.
const moveOutcomeMarker = (nodes: Node[], ownerId: string, outcome: WorkflowEditionFormValues['requestAccessOutcome']) => {
  if (!outcome) return nodes;
  return nodes.map((node) => (
    node.type === WorkflowNodeType.status && node.id !== ownerId && node.data?.requestAccessOutcome === outcome
      ? {
          ...node,
          data: {
            ...node.data,
            requestAccessOutcome: null,
            ...(outcome === 'APPROVED' ? { onEnter: withoutDefaultShareRequestedEntities(node.data.onEnter) } : {}),
          },
        }
      : node
  ));
};

export const useWorkflowForm = (selectedElement: Node | Edge, onClose: () => void) => {
  const { t_i18n } = useFormatter();
  const { setNodes } = useReactFlow();

  const addStatus = useAddStatus(selectedElement);
  const deleteElement = useDeleteElement();

  // 1. State Flags
  const isStatus = selectedElement?.type === WorkflowNodeType.status || selectedElement?.type === WorkflowNodeType.placeholder;
  const isNewStatus = selectedElement?.type === WorkflowNodeType.placeholder;

  // 2. Computed Titles & Schemas
  const drawerTitle = useMemo(() => {
    if (isStatus) return isNewStatus ? t_i18n('Add status') : t_i18n('Edit status');
    return t_i18n('Edit transition');
  }, [isStatus, isNewStatus, t_i18n]);

  const validationSchema = useMemo(
    () => getValidationSchema(isStatus, t_i18n),
    [isStatus, t_i18n],
  );

  // 3. Handlers
  const onSubmit = (values: WorkflowEditionFormValues) => {
    if (isNewStatus) {
      addStatus(values);
      if (values.requestAccessOutcome) {
        setNodes((nodes) => moveOutcomeMarker(nodes, values.statusTemplate.id, values.requestAccessOutcome));
      }
    } else {
      setNodes((nodes) =>
        moveOutcomeMarker(nodes, selectedElement.id, values.requestAccessOutcome).map((node) =>
          node.id === selectedElement.id
            ? { ...node, data: { ...node.data, ...values } }
            : node,
        ),
      );
    }
    onClose();
  };

  const onDelete = () => {
    if (selectedElement?.id) {
      deleteElement(selectedElement.id);
    }
    onClose();
  };

  return {
    drawerTitle,
    isStatus,
    isNewStatus,
    validationSchema,
    onSubmit,
    onDelete,
  };
};

import { FormikHelpers } from 'formik';
import { useMemo } from 'react';
import { Node, Edge, useReactFlow } from 'reactflow';
import * as Yup from 'yup';
import { useFormatter } from '../../../../../../components/i18n';
import useAddStatus from './useAddStatus';
import useDeleteElement from './useDeleteElement';
import { WorkflowEditionFormValues } from '../WorkflowEditionDrawer';
import { WorkflowNodeType } from '../utils';

// Validation Factory
const getValidationSchema = (isStatus: boolean, t: (s: string) => string) => {
  if (isStatus) {
    return Yup.object().shape({
      statusTemplate: Yup.object().required(t('This field is required')),
    });
  }
  return Yup.object().shape({
    event: Yup.string().required(t('This field is required')),
  });
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
    } else {
      setNodes((nodes) =>
        nodes.map((node) =>
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

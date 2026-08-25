import React from 'react';
import { DataColumns } from '../../../../components/list_lines';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import ItemDueDate from '../../../../components/ItemDueDate';
import ItemStatus from '../../../../components/ItemStatus';
import { EMPTY_VALUE } from '../../../../utils/String';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { defaultRender } from '../../../../components/dataGrid/dataTableUtils';
import { TasksLine_node$data } from '@components/cases/__generated__/TasksLine_node.graphql';
import useAuth from '../../../../utils/hooks/useAuth';

export const useTasksDataColumns = (): DataColumns => {
  const { platformModuleHelpers: { isFeatureEnable } } = useAuth();
  const isWorkflowInstanceEnabled = isFeatureEnable('ENTITIES_WORKFLOW');
  return {
    name: {
      label: 'Name',
      width: '35%',
      isSortable: true,
      render: (task: TasksLine_node$data) => {
        return defaultRender(getMainRepresentative(task));
      },
    },
    due_date: {
      label: 'Due Date',
      width: '19%',
      isSortable: true,
      render: (task: TasksLine_node$data) => (
        <ItemDueDate due_date={task.due_date} variant="inList" />
      ),
    },
    objectAssignee: {
      label: 'Assignees',
      width: '17%',
      isSortable: true,

      render: (task: TasksLine_node$data) => ((task.objectAssignee ?? []).length > 0
        ? (task.objectAssignee ?? []).map((node) => node.name).join(', ')
        : EMPTY_VALUE),
    },
    objectLabel: {
      label: 'Labels',
      width: '17%',
      isSortable: false,
      render: (task: TasksLine_node$data) => (
        <StixCoreObjectLabels variant="inList" labels={task.objectLabel} />
      ),
    },
    ...(isWorkflowInstanceEnabled
      ? {
          workflowInstance: {
            label: 'Status',
            width: '12%',
            isSortable: true,
            render: (task: TasksLine_node$data) => {
              const workflowInstance = task.workflowInstance as unknown as {
                id?: string;
                currentStatus?: { template: { id: string; name: string; color: string } | null } | null;
              } | null;
              // A workflowInstance id prefixed with 'initial-' means it has not been migrated
              // yet (no real WorkflowInstance entity exists) so fall back to the legacy status.
              const isNotMigrated = (workflowInstance?.id ?? '').startsWith('initial-');
              const currentStatus = isNotMigrated ? (task.status ?? null) : (workflowInstance?.currentStatus ?? null);
              return (
                <ItemStatus
                  status={currentStatus}
                  disabled={!currentStatus}
                />
              );
            },
          },
        }
      : {
          x_opencti_workflow_id: {
            label: 'Status',
            width: '12%',
            isSortable: true,
            render: (task: TasksLine_node$data) => (
              <ItemStatus
                status={task.status}
                disabled={!task.workflowEnabled}
              />
            ),
          },
        }),
  };
};

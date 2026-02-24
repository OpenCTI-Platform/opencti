import React from 'react';
import { TasksLine_node$data } from './__generated__/TasksLine_node.graphql';
import { DataColumns } from '../../../../components/list_lines';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import ItemStatus from '../../../../components/ItemStatus';
import ItemDueDate from '../../../../components/ItemDueDate';
import { EMPTY_VALUE } from '../../../../utils/String';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { defaultRender } from '../../../../components/dataGrid/dataTableUtils';

export const tasksDataColumns: DataColumns = {
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
    width: '12%',
    isSortable: true,
    render: (task: TasksLine_node$data) => (
      <ItemDueDate due_date={task.due_date} variant="inList" />
    ),
  },
  objectAssignee: {
    label: 'Assignees',
    width: '18%',
    isSortable: true,

    render: (task: TasksLine_node$data) => ((task.objectAssignee ?? []).length > 0
      ? (task.objectAssignee ?? []).map((node) => node.name).join(', ')
      : EMPTY_VALUE),
  },
  objectLabel: {
    label: 'Labels',
    width: '18%',
    isSortable: false,
    render: (task: TasksLine_node$data) => (
      <StixCoreObjectLabels variant="inList" labels={task.objectLabel} />
    ),
  },
  x_opencti_workflow_id: {
    label: 'Status',
    width: '15%',
    isSortable: true,
    render: (task: TasksLine_node$data) => (
      <ItemStatus
        status={task.status}
        disabled={!task.workflowEnabled}
      />
    ),
  },
};

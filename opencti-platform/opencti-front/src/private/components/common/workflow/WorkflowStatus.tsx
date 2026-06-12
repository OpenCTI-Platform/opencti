import React, { FunctionComponent } from 'react';
import { useFragment } from 'react-relay';
import { Tooltip } from '@mui/material';
import { CommentOutlined } from '@mui/icons-material';
import ItemStatus from '../../../../components/ItemStatus';
import { workflowStatusFragment } from './workflowStatus.graphql';
import { workflowStatus_data$key } from './__generated__/workflowStatus_data.graphql';

export { workflowStatusFragment } from './workflowStatus.graphql';
export { WorkflowTransitions } from './WorkflowTransitions';

interface WorkflowStatusProps {
  data: workflowStatus_data$key;
}

const WorkflowStatus: FunctionComponent<WorkflowStatusProps> = ({ data }) => {
  const draft = useFragment(workflowStatusFragment, data);

  if (!draft.workflowInstance) {
    return null;
  }

  const { workflowInstance } = draft;
  const currentStatus = workflowInstance.currentStatus;
  const lastComment = workflowInstance.lastHistoryEntry?.comment ?? null;

  return (
    <>
      {lastComment && (
        <Tooltip title={lastComment} arrow>
          <CommentOutlined fontSize="small" sx={{ marginRight: 0.5, color: 'text.secondary' }} />
        </Tooltip>
      )}
      <ItemStatus status={currentStatus} />
    </>
  );
};

export default WorkflowStatus;

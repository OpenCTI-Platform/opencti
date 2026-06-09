import React, { FunctionComponent, useState } from 'react';
import { useFragment } from 'react-relay';
import { Box, Popover, Typography } from '@mui/material';
import { CommentOutlined } from '@mui/icons-material';
import ItemStatus from '../../../../components/ItemStatus';
import { workflowStatusFragment } from './workflowStatus.graphql';
import IconButton from '../../../../components/common/button/IconButton';
import { workflowStatus_data$key } from '@components/common/workflow/__generated__/WorkflowStatus_data.graphql';
import { useFormatter } from '../../../../components/i18n';

export { workflowStatusFragment } from './workflowStatus.graphql';
export { WorkflowTransitions } from './WorkflowTransitions';

interface WorkflowStatusProps {
  data: workflowStatus_data$key;
}

const WorkflowStatus: FunctionComponent<WorkflowStatusProps> = ({ data }) => {
  const { t_i18n } = useFormatter();
  const draft = useFragment(workflowStatusFragment, data);
  const [commentAnchorEl, setCommentAnchorEl] = useState<HTMLButtonElement | null>(null);

  if (!draft.workflowInstance) {
    return null;
  }

  const { workflowInstance } = draft;
  const currentStatus = workflowInstance.currentStatus;
  const lastComment = workflowInstance.lastHistoryEntry?.comment ?? null;

  return (
    <>
      {lastComment && (
        <>
          <IconButton
            aria-label={t_i18n('View last comment')}
            onClick={(e) => setCommentAnchorEl(e.currentTarget)}
            sx={{ marginRight: 0.5 }}
          >
            <CommentOutlined fontSize="small" />
          </IconButton>
          <Popover
            open={Boolean(commentAnchorEl)}
            anchorEl={commentAnchorEl}
            onClose={() => setCommentAnchorEl(null)}
            anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
            transformOrigin={{ vertical: 'bottom', horizontal: 'center' }}
          >
            <Box sx={{ p: 2, maxWidth: 400 }}>
              <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
                {lastComment}
              </Typography>
            </Box>
          </Popover>
        </>
      )}
      <ItemStatus status={currentStatus} />
    </>
  );
};

export default WorkflowStatus;

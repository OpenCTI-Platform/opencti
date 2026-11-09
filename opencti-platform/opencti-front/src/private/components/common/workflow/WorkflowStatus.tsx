import React, { FunctionComponent, ReactNode, useState } from 'react';
import { useFragment } from 'react-relay';
import { Box, Popover, Typography } from '@mui/material';
import { CommentOutlined } from '@mui/icons-material';
import ItemStatus from '../../../../components/ItemStatus';
import { workflowStatusFragment, workflowStatusStixDomainObjectFragment } from './WorkflowStatus.graphql';
import { WorkflowStatus_data$key } from './__generated__/WorkflowStatus_data.graphql';
import IconButton from '../../../../components/common/button/IconButton';
import { useFormatter } from '../../../../components/i18n';
import useHelper from '../../../../utils/hooks/useHelper';
import { isWorkflowUiEnabledForType } from './workflowFeatureFlag';
import type { WorkflowStatusStixDomainObject_data$data, WorkflowStatusStixDomainObject_data$key } from './__generated__/WorkflowStatusStixDomainObject_data.graphql';
import { useGetCurrentUserAccessRight } from '../../../../utils/authorizedMembers';
import useAuth from '../../../../utils/hooks/useAuth';
import { isBypassUser } from '../../../../utils/hooks/useGranted';
import Label from '../../../../components/common/label/Label';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
export { WorkflowTransitions } from './WorkflowTransitions';

interface WorkflowStatusProps {
  data: WorkflowStatus_data$key;
  entityType?: string;
}

const WorkflowStatusView = ({ workflowInstance, fallback = null, hideStatus = false }: {
  workflowInstance: WorkflowStatusStixDomainObject_data$data['workflowInstance'];
  fallback?: ReactNode;
  hideStatus?: boolean;
}) => {
  const { t_i18n } = useFormatter();
  const [commentAnchorEl, setCommentAnchorEl] = useState<HTMLButtonElement | null>(null);

  if (!workflowInstance) {
    return fallback;
  }

  const currentStatus = workflowInstance.currentStatus;
  const lastComment = workflowInstance.lastHistoryEntry?.comment ?? null;

  return (
    <>
      {lastComment && (
        <>
          <IconButton
            aria-label={t_i18n('View last comment')}
            onClick={(e) => setCommentAnchorEl(e.currentTarget)}
            className="p-4"
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
      {!hideStatus && (currentStatus || fallback === null ? <ItemStatus status={currentStatus} /> : fallback)}
    </>
  );
};

const WorkflowStatus: FunctionComponent<WorkflowStatusProps> = ({ data, entityType = 'DraftWorkspace' }) => {
  const { isFeatureEnable } = useHelper();
  const draft = useFragment(workflowStatusFragment, data);
  return isWorkflowUiEnabledForType(entityType, isFeatureEnable)
    ? <WorkflowStatusView workflowInstance={draft.workflowInstance} />
    : null;
};

export const WorkflowStatusForEntity = ({ data, entityType, fallback = null, children }: {
  data: WorkflowStatusStixDomainObject_data$key;
  entityType: string;
  fallback?: ReactNode;
  children?: ReactNode;
}) => {
  const { isFeatureEnable } = useHelper();
  const { me } = useAuth();
  const entity = useFragment(workflowStatusStixDomainObjectFragment, data);
  const { canEdit } = useGetCurrentUserAccessRight(entity.currentUserAccessRight);
  return isWorkflowUiEnabledForType(entityType, isFeatureEnable)
    ? (
        <>
          {entity.workflowInstance && canEdit && children}
          <WorkflowStatusView workflowInstance={entity.workflowInstance} fallback={fallback} hideStatus={!!children && canEdit && isBypassUser(me)} />
        </>
      )
    : fallback;
};

export const WorkflowClosingReasonForEntity = ({ data, entityType }: {
  data: WorkflowStatusStixDomainObject_data$key;
  entityType: string;
}) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const entity = useFragment(workflowStatusStixDomainObjectFragment, data);
  if (!isWorkflowUiEnabledForType(entityType, isFeatureEnable) || !entity.x_opencti_closing_reason) {
    return null;
  }
  return (
    <>
      <Label sx={{ marginTop: 2 }}>
        {t_i18n('Closing reason')}
      </Label>
      <ItemOpenVocab type="closing_reason_ov" value={entity.x_opencti_closing_reason} />
    </>
  );
};

export default WorkflowStatus;

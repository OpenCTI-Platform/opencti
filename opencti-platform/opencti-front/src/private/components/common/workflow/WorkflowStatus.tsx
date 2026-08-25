import { AssignmentTurnedInOutlined, CommentOutlined } from '@mui/icons-material';
import { Box, Popover, Typography } from '@mui/material';
import { FunctionComponent, useState } from 'react';
import { useFragment } from 'react-relay';
import IconButton from '../../../../components/common/button/IconButton';
import { useFormatter } from '../../../../components/i18n';
import ItemStatus from '../../../../components/ItemStatus';
import useHelper from '../../../../utils/hooks/useHelper';
import { WorkflowStatus_data$key } from './__generated__/WorkflowStatus_data.graphql';
import { WorkflowStatusStixDomainObject_data$key } from './__generated__/WorkflowStatusStixDomainObject_data.graphql';
import { isWorkflowUiEnabledForType } from './workflowFeatureFlag';
import { workflowStatusFragment, workflowStatusStixDomainObjectFragment } from './WorkflowStatus.graphql';
export { WorkflowTransitions, WorkflowTransitionsForEntity } from './WorkflowTransitions';

interface WorkflowStatusProps {
  data: WorkflowStatus_data$key;
  // Entity type the displayed WorkflowInstance belongs to. Defaults to 'DraftWorkspace' (the only
  // caller today, via DraftToolbar.tsx); other entity types are gated behind the ENTITIES_WORKFLOW
  // feature flag (plan.md Task 5, Step 2).
  entityType?: string;
}

interface WorkflowStatusForEntityProps {
  data: WorkflowStatusStixDomainObject_data$key;
  entityType: string;
}

// Task 9: presentational view shared by the DraftWorkspace-bound `WorkflowStatus` and the generic
// StixDomainObject-bound `WorkflowStatusForEntity` — both resolve their own Relay fragment then
// delegate to this component with plain, already-resolved data.
const WorkflowStatusView: FunctionComponent<{
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  workflowInstance: any;
  // The generic entity overview renders the closing reason as subtext below the status dropdown
  // instead, so it isn't squeezed inside the clickable pill.
  showClosingReason?: boolean;
}> = ({ workflowInstance, showClosingReason = true }) => {
  const { t_i18n } = useFormatter();
  const [commentAnchorEl, setCommentAnchorEl] = useState<HTMLButtonElement | null>(null);
  const [closingReasonAnchorEl, setClosingReasonAnchorEl] = useState<HTMLButtonElement | null>(null);

  const currentStatus = workflowInstance.currentStatus;
  const lastComment = workflowInstance.lastHistoryEntry?.comment ?? null;
  const lastClosingReason = workflowInstance.lastHistoryEntry?.closing_reason ?? null;

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
      {showClosingReason && lastClosingReason && (
        <>
          <IconButton
            aria-label={t_i18n('View closing reason')}
            onClick={(e) => setClosingReasonAnchorEl(e.currentTarget)}
            sx={{ marginRight: 0.5 }}
          >
            <AssignmentTurnedInOutlined fontSize="small" />
          </IconButton>
          <Popover
            open={Boolean(closingReasonAnchorEl)}
            anchorEl={closingReasonAnchorEl}
            onClose={() => setClosingReasonAnchorEl(null)}
            anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
            transformOrigin={{ vertical: 'bottom', horizontal: 'center' }}
          >
            <Box sx={{ p: 2, maxWidth: 400 }}>
              <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
                {lastClosingReason}
              </Typography>
            </Box>
          </Popover>
        </>
      )}
      <ItemStatus status={currentStatus} variant="plain" />
    </>
  );
};

const WorkflowStatus: FunctionComponent<WorkflowStatusProps> = ({ data, entityType = 'DraftWorkspace' }) => {
  const { isFeatureEnable } = useHelper();
  const draft = useFragment(workflowStatusFragment, data);

  if (!draft.workflowInstance || !isWorkflowUiEnabledForType(entityType, isFeatureEnable)) {
    return null;
  }

  return <WorkflowStatusView workflowInstance={draft.workflowInstance} />;
};

// Task 9: generic counterpart for any StixDomainObject-implementing entity type, mounted from
// StixDomainObjectOverview.jsx, gated by the ENTITIES_WORKFLOW feature flag.
export const WorkflowStatusForEntity: FunctionComponent<WorkflowStatusForEntityProps> = ({ data, entityType }) => {
  const { isFeatureEnable } = useHelper();
  const entity = useFragment(workflowStatusStixDomainObjectFragment, data);

  if (!entity.workflowInstance || !isWorkflowUiEnabledForType(entityType, isFeatureEnable)) {
    return null;
  }

  return <WorkflowStatusView workflowInstance={entity.workflowInstance} showClosingReason={false} />;
};

// The overview page renders this outside the status dropdown, as a link under the status +
// actions row, instead of the icon-triggered popover used inline elsewhere (e.g. draft toolbar).
export const WorkflowClosingReasonForEntity: FunctionComponent<WorkflowStatusForEntityProps> = ({ data, entityType }) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const entity = useFragment(workflowStatusStixDomainObjectFragment, data);
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);

  if (!entity.workflowInstance || !isWorkflowUiEnabledForType(entityType, isFeatureEnable)) {
    return null;
  }

  const lastClosingReason = entity.workflowInstance.lastHistoryEntry?.closing_reason ?? null;
  if (!lastClosingReason) {
    return null;
  }

  return (
    <>
      <Typography
        variant="caption"
        color="text.secondary"
        onClick={(e) => setAnchorEl(e.currentTarget)}
        sx={{ display: 'block', width: 'fit-content', cursor: 'pointer', textDecoration: 'underline' }}
      >
        {t_i18n('Closing reason')}
      </Typography>
      <Popover
        open={Boolean(anchorEl)}
        anchorEl={anchorEl}
        onClose={() => setAnchorEl(null)}
        anchorOrigin={{ vertical: 'top', horizontal: 'left' }}
        transformOrigin={{ vertical: 'bottom', horizontal: 'left' }}
      >
        <Box sx={{ p: 2, maxWidth: 400 }}>
          <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
            {lastClosingReason}
          </Typography>
        </Box>
      </Popover>
    </>
  );
};

export default WorkflowStatus;

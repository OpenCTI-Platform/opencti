import Dialog from '@common/dialog/Dialog';
import { SwapHorizOutlined } from '@mui/icons-material';
import { FormControlLabel, Menu, MenuItem, Switch, TextField } from '@mui/material';
import React, { FunctionComponent, useState } from 'react';
import { useMutation } from 'react-relay';
import Button from '../../../../components/common/button/Button';
import IconButton from '../../../../components/common/button/IconButton';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import useAuth from '../../../../utils/hooks/useAuth';
import { isBypassUser } from '../../../../utils/hooks/useGranted';
import useHelper from '../../../../utils/hooks/useHelper';
import { StatusScopeEnum } from '../../../../utils/statusConstants';
import type { StatusFieldStatusesSearchQuery$data } from '../form/__generated__/StatusFieldStatusesSearchQuery.graphql';
import { statusFieldStatusesSearchQuery } from '../form/StatusField';
import type { WorkflowSetStatusMutation as WorkflowSetStatusMutationType } from './__generated__/WorkflowSetStatusMutation.graphql';
import { isWorkflowUiEnabledForType } from './workflowFeatureFlag';
import { workflowSetStatusMutation } from './WorkflowStatus.graphql';

interface WorkflowBypassStatusProps {
  entityId: string;
  entityType: string;
}

interface StatusOption {
  label: string;
  value: string;
  order: number;
}

// Task 9.3: bypass-update popover — admin-only (isBypassUser), lets the user jump the entity
// directly to any state mapped in the published workflow, without going through
// `allowedTransitions`, in either of two modes: status-only, or status + onExit/onEnter actions
// (toggled via `applyTransitionActions`). Calls the `setWorkflowStatus` mutation (workflow-domain.ts).
export const WorkflowBypassStatus: FunctionComponent<WorkflowBypassStatusProps> = ({ entityId, entityType }) => {
  const { t_i18n } = useFormatter();
  const { me } = useAuth();
  const { isFeatureEnable } = useHelper();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [statuses, setStatuses] = useState<StatusOption[]>([]);
  const [selectedStatus, setSelectedStatus] = useState<StatusOption | null>(null);
  const [applyTransitionActions, setApplyTransitionActions] = useState<boolean>(true);
  const [comment, setComment] = useState<string>('');

  const [commit, committing] = useMutation<WorkflowSetStatusMutationType>(workflowSetStatusMutation);

  if (!isBypassUser(me) || !isWorkflowUiEnabledForType(entityType, isFeatureEnable)) {
    return null;
  }

  const handleOpenMenu = (event: React.MouseEvent<HTMLButtonElement>) => {
    setAnchorEl(event.currentTarget);
    fetchQuery(statusFieldStatusesSearchQuery, {
      first: 100,
      filters: {
        mode: 'and',
        filterGroups: [],
        filters: [
          { key: 'type', values: [entityType] },
          { key: 'scope', values: [StatusScopeEnum.GLOBAL] },
        ],
      },
      orderBy: 'order',
      orderMode: 'asc',
    })
      .toPromise()
      .then((data) => {
        const queryData = data as StatusFieldStatusesSearchQuery$data;
        const edges = queryData?.statuses?.edges ?? [];
        setStatuses(
          edges
            .filter((edge) => edge?.node?.template != null)
            .map((edge) => ({
              label: edge.node.template!.name,
              value: edge.node.id,
              order: edge.node.order,
            })),
        );
      });
  };

  const handleCloseMenu = () => setAnchorEl(null);

  const handleSelectStatus = (status: StatusOption) => {
    setSelectedStatus(status);
    setAnchorEl(null);
  };

  const handleCloseDialog = () => {
    setSelectedStatus(null);
    setApplyTransitionActions(true);
    setComment('');
  };

  const handleApply = () => {
    if (!selectedStatus) return;
    commit({
      variables: {
        entityId,
        targetStatusId: selectedStatus.value,
        applyTransitionActions,
        comment: comment.trim() || undefined,
      },
      onCompleted: (response) => {
        if (response.setWorkflowStatus?.success) {
          MESSAGING$.notifySuccess(t_i18n('Status updated'));
        } else {
          MESSAGING$.notifyError(response.setWorkflowStatus?.reason ?? t_i18n('Status update failed'));
        }
        handleCloseDialog();
      },
    });
  };

  return (
    <>
      <IconButton aria-label={t_i18n('Bypass status')} onClick={handleOpenMenu}>
        <SwapHorizOutlined fontSize="small" />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleCloseMenu}>
        {statuses.map((status) => (
          <MenuItem key={status.value} onClick={() => handleSelectStatus(status)}>
            {status.label}
          </MenuItem>
        ))}
      </Menu>
      <Dialog
        open={selectedStatus !== null}
        onClose={handleCloseDialog}
        title={t_i18n('Bypass status')}
      >
        <TextField
          fullWidth
          multiline
          minRows={2}
          label={t_i18n('Comment')}
          value={comment}
          onChange={(e) => setComment(e.target.value)}
          variant="outlined"
          size="small"
          sx={{ mb: 2 }}
        />
        <FormControlLabel
          control={(
            <Switch
              checked={applyTransitionActions}
              onChange={(e) => setApplyTransitionActions(e.target.checked)}
            />
          )}
          label={t_i18n('Apply onExit/onEnter actions of the crossed states')}
        />
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
          <Button variant="secondary" onClick={handleCloseDialog}>
            {t_i18n('Cancel')}
          </Button>
          <Button onClick={handleApply} disabled={committing}>
            {t_i18n('Apply')}
          </Button>
        </div>
      </Dialog>
    </>
  );
};

export default WorkflowBypassStatus;

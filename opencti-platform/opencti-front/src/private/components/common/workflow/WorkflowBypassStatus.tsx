import Dialog from '@common/dialog/Dialog';
import { KeyboardArrowDownOutlined } from '@mui/icons-material';
import { Box, FormControlLabel, Menu, MenuItem, Switch, TextField } from '@mui/material';
import { alpha } from '@mui/material/styles';
import React, { FunctionComponent, useEffect, useState } from 'react';
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
  // Raw current state id (unprefixed, e.g. `workflowInstance.currentState`) — used only to exclude
  // the entity's current status from the "jump to" list, so the chevron reflects whether there is
  // actually another status to jump to.
  currentStateId?: string;
  // The status display to wrap — made clickable as a whole (not just the chevron) when the bypass
  // control is actually usable for this entity.
  children?: React.ReactNode;
}

interface StatusOption {
  label: string;
  value: string;
  templateId: string;
  order: number;
  color: string;
}

// Task 9.3: bypass-update popover — admin-only (isBypassUser), lets the user jump the entity
// directly to any state mapped in the published workflow, without going through
// `allowedTransitions`, in either of two modes: status-only, or status + onExit/onEnter actions
// (toggled via `applyTransitionActions`). Calls the `setWorkflowStatus` mutation (workflow-domain.ts).
export const WorkflowBypassStatus: FunctionComponent<WorkflowBypassStatusProps> = ({ entityId, entityType, currentStateId, children }) => {
  const { t_i18n } = useFormatter();
  const { me } = useAuth();
  const { isFeatureEnable } = useHelper();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  // `null` = not fetched yet (eager fetch on mount, so we know upfront whether the chevron is
  // actually usable — showing it regardless would let a user open an empty/single-entry menu).
  const [statuses, setStatuses] = useState<StatusOption[] | null>(null);
  const [selectedStatus, setSelectedStatus] = useState<StatusOption | null>(null);
  const [applyTransitionActions, setApplyTransitionActions] = useState<boolean>(true);
  const [comment, setComment] = useState<string>('');

  const [commit, committing] = useMutation<WorkflowSetStatusMutationType>(workflowSetStatusMutation);

  const enabled = isBypassUser(me) && isWorkflowUiEnabledForType(entityType, isFeatureEnable);

  useEffect(() => {
    if (!enabled) return;
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
              templateId: edge.node.template!.id,
              order: edge.node.order,
              color: edge.node.template!.color,
            })),
        );
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, entityType]);

  const otherStatuses = (statuses ?? []).filter((status) => !currentStateId || status.templateId !== currentStateId);

  if (!enabled || otherStatuses.length === 0) {
    return <>{children}</>;
  }

  const handleOpenMenu = (event: React.MouseEvent<HTMLElement>) => setAnchorEl(event.currentTarget);

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
      <Box
        onClick={handleOpenMenu}
        sx={{
          display: 'flex',
          alignItems: 'center',
          cursor: 'pointer',
          height: '36px',
          padding: '8px 16px',
          borderRadius: '4px',
          borderLeft: '2px solid',
          borderLeftColor: anchorEl ? 'primary.main' : 'transparent',
          '&:hover': { bgcolor: 'action.hover' },
        }}
      >
        {children}
        {/* Purely decorative here — the whole row above already triggers the menu, so this
            shouldn't have its own distinct hover highlight. */}
        <IconButton
          aria-label={t_i18n('Bypass status')}
          size="small"
          disableRipple
          sx={{ '&:hover': { backgroundColor: 'transparent' } }}
        >
          <KeyboardArrowDownOutlined fontSize="small" />
        </IconButton>
      </Box>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleCloseMenu}
        slotProps={{ paper: { elevation: 1 } }}
      >
        {otherStatuses.map((status, index) => (
          <MenuItem
            key={status.value}
            onClick={() => handleSelectStatus(status)}
            sx={{
              borderBottom: index < otherStatuses.length - 1 ? '1px solid' : 'none',
              borderBottomColor: 'divider',
            }}
          >
            <Box
              component="span"
              sx={{
                fontSize: 11,
                fontWeight: 700,
                lineHeight: '16px',
                borderRadius: '4px',
                px: '4px',
                mr: '4px',
                color: status.color,
                bgcolor: alpha(status.color, 0.15),
              }}
            >
              {status.order}
            </Box>
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

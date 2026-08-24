import { SwapHorizOutlined } from '@mui/icons-material';
import { FormControlLabel, Menu, MenuItem, Switch } from '@mui/material';
import React, { FunctionComponent, useState } from 'react';
import Button from '../../../../components/common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import { isBypassUser } from '../../../../utils/hooks/useGranted';
import useHelper from '../../../../utils/hooks/useHelper';
import { StatusScopeEnum } from '../../../../utils/statusConstants';
import type { StatusFieldStatusesSearchQuery$data } from '../form/__generated__/StatusFieldStatusesSearchQuery.graphql';
import { statusFieldStatusesSearchQuery } from '../form/StatusField';
import { isWorkflowUiEnabledForType } from './workflowFeatureFlag';

interface WorkflowBypassMassStatusProps {
  entityType: string;
  me: { id: string; capabilities: readonly { name: string }[] };
  onApply: (statusId: string, applyTransitionActions: boolean) => void;
  disabled?: boolean;
}

interface StatusOption {
  label: string;
  value: string;
  order: number;
}

// Task 12: bypass-only mass-edit variant of the plain 'x_opencti_workflow_id' toolbar field —
// UI-only, no mutation of its own. Lets a bypass user pick a target status + toggle
// onExit/onEnter actions for a bulk selection; the caller (DataTableToolBar.jsx) turns
// `onApply`'s (statusId, applyTransitionActions) into the actionsInputs[i] shape that the
// existing task-mutation plumbing already knows how to submit (the pre-existing
// ACTION_TYPE_WORKFLOW_TRANSITION bypass path in taskManager.js).
export const WorkflowBypassMassStatus: FunctionComponent<WorkflowBypassMassStatusProps> = ({ entityType, me, onApply, disabled }) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [statuses, setStatuses] = useState<StatusOption[]>([]);
  const [selectedStatus, setSelectedStatus] = useState<StatusOption | null>(null);
  const [applyTransitionActions, setApplyTransitionActions] = useState<boolean>(true);

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

  const handleReset = () => {
    setSelectedStatus(null);
    setApplyTransitionActions(true);
  };

  const handleApply = () => {
    if (!selectedStatus) return;
    onApply(selectedStatus.value, applyTransitionActions);
    handleReset();
  };

  return (
    <>
      <Button
        variant="secondary"
        disabled={disabled}
        onClick={handleOpenMenu}
        startIcon={<SwapHorizOutlined fontSize="small" />}
      >
        {selectedStatus ? selectedStatus.label : t_i18n('Select a status')}
      </Button>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleCloseMenu}>
        {statuses.map((status) => (
          <MenuItem key={status.value} onClick={() => handleSelectStatus(status)}>
            {status.label}
          </MenuItem>
        ))}
      </Menu>
      {selectedStatus && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}>
          <FormControlLabel
            control={(
              <Switch
                checked={applyTransitionActions}
                onChange={(e) => setApplyTransitionActions(e.target.checked)}
              />
            )}
            label={t_i18n('Apply onExit/onEnter actions of the crossed states')}
          />
          <Button variant="secondary" onClick={handleReset}>
            {t_i18n('Cancel')}
          </Button>
          <Button onClick={handleApply}>
            {t_i18n('Apply')}
          </Button>
        </div>
      )}
    </>
  );
};

export default WorkflowBypassMassStatus;

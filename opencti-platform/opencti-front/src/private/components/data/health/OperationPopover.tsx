import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import MoreVert from '@mui/icons-material/MoreVert';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import DialogActions from '@mui/material/DialogActions';
import DialogContentText from '@mui/material/DialogContentText';
import CircularProgress from '@mui/material/CircularProgress';
import Typography from '@mui/material/Typography';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import { PopoverProps } from '@mui/material/Popover';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { fetchQuery } from '../../../../relay/environment';
import { OperationPopoverDryRunQuery$data } from './__generated__/OperationPopoverDryRunQuery.graphql';

const operationPopoverRequestRunMutation = graphql`
  mutation OperationPopoverRequestRunMutation($operation_name: String!) {
    dataSanityOperationRequestRun(operation_name: $operation_name)
  }
`;

const operationPopoverStopMutation = graphql`
  mutation OperationPopoverStopMutation($operation_name: String!) {
    dataSanityOperationStop(operation_name: $operation_name)
  }
`;

const operationPopoverDryRunQuery = graphql`
  query OperationPopoverDryRunQuery($operation_name: String!) {
    dataSanityOperationDryRun(operation_name: $operation_name) {
      estimated_impact {
        key
        count
      }
    }
  }
`;

interface OperationPopoverProps {
  operationName: string;
  /** An operation can only be stopped when it is running or scheduled. */
  isStoppable: boolean;
  /** Called after a mutation succeeded, to let the parent refresh the operation list. */
  onUpdate?: () => void;
}

const OperationPopover: FunctionComponent<OperationPopoverProps> = ({ operationName, isStoppable, onUpdate }) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);
  const [displayScheduleRun, setDisplayScheduleRun] = useState(false);
  const [scheduling, setScheduling] = useState(false);
  const [displayStop, setDisplayStop] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [displayDryRun, setDisplayDryRun] = useState(false);
  const [dryRunLoading, setDryRunLoading] = useState(false);
  const [dryRunResult, setDryRunResult] = useState<OperationPopoverDryRunQuery$data['dataSanityOperationDryRun'] | null>(null);

  const handleOpen = (event: React.SyntheticEvent) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  // Schedule a run
  const [commitScheduleRun] = useApiMutation(operationPopoverRequestRunMutation);

  const handleOpenScheduleRun = () => {
    setDisplayScheduleRun(true);
    handleClose();
  };

  const handleCloseScheduleRun = () => {
    setDisplayScheduleRun(false);
  };

  const submitScheduleRun = () => {
    setScheduling(true);
    commitScheduleRun({
      variables: { operation_name: operationName },
      onCompleted: () => {
        setScheduling(false);
        handleCloseScheduleRun();
        onUpdate?.();
      },
      onError: () => {
        setScheduling(false);
      },
    });
  };

  // Stop the operation (marks it as done even if currently running)
  const [commitStop] = useApiMutation(operationPopoverStopMutation);

  const handleOpenStop = () => {
    setDisplayStop(true);
    handleClose();
  };

  const handleCloseStop = () => {
    setDisplayStop(false);
  };

  const submitStop = () => {
    setStopping(true);
    commitStop({
      variables: { operation_name: operationName },
      onCompleted: () => {
        setStopping(false);
        handleCloseStop();
        onUpdate?.();
      },
      onError: () => {
        setStopping(false);
      },
    });
  };

  // Estimate impact (dry run)
  const handleOpenDryRun = async () => {
    setDisplayDryRun(true);
    setDryRunLoading(true);
    setDryRunResult(null);
    handleClose();
    try {
      const result = await fetchQuery(
        operationPopoverDryRunQuery,
        { operation_name: operationName },
      ).toPromise() as OperationPopoverDryRunQuery$data;
      setDryRunResult(result.dataSanityOperationDryRun);
    } finally {
      setDryRunLoading(false);
    }
  };

  const handleCloseDryRun = () => {
    setDisplayDryRun(false);
    setDryRunResult(null);
  };

  return (
    <div style={{ margin: 0 }}>
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
        style={{ marginTop: 3 }}
        color="primary"
      >
        <MoreVert />
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
      >
        <MenuItem onClick={handleOpenScheduleRun}>
          {t_i18n('Schedule a run')}
        </MenuItem>
        <MenuItem onClick={handleOpenStop} disabled={!isStoppable} data-testid="stop-operation-menu-item">
          {t_i18n('Stop')}
        </MenuItem>
        <MenuItem onClick={handleOpenDryRun}>
          {t_i18n('Estimate impact')}
        </MenuItem>
      </Menu>
      <Dialog
        open={displayScheduleRun}
        onClose={handleCloseScheduleRun}
        title={t_i18n('Schedule a run')}
      >
        <DialogContentText>
          {t_i18n('Do you want to schedule a run for this operation?')}
        </DialogContentText>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={handleCloseScheduleRun}
            disabled={scheduling}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitScheduleRun}
            disabled={scheduling}
          >
            {t_i18n('Schedule')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={displayStop}
        onClose={handleCloseStop}
        title={t_i18n('Stop the operation')}
      >
        <DialogContentText>
          {t_i18n('Do you want to stop this operation? It will be marked as done, even if it is currently running, and can be scheduled again afterwards.')}
        </DialogContentText>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={handleCloseStop}
            disabled={stopping}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitStop}
            disabled={stopping}
            data-testid="stop-operation-confirm-button"
          >
            {t_i18n('Stop')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={displayDryRun}
        onClose={handleCloseDryRun}
        title={t_i18n('Estimated impact')}
      >
        {dryRunLoading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 20 }}>
            <CircularProgress />
          </div>
        ) : (
          <>
            {dryRunResult && dryRunResult.estimated_impact.length > 0 ? (
              dryRunResult.estimated_impact.map((item) => (
                <Typography key={item.key} variant="body2" sx={{ mb: 1 }}>
                  {item.key}: <strong>{item.count}</strong>
                </Typography>
              ))
            ) : (
              <Typography variant="body2" color="text.secondary">
                {t_i18n('No impact estimated.')}
              </Typography>
            )}
          </>
        )}
        <DialogActions>
          <Button onClick={handleCloseDryRun}>
            {t_i18n('Close')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default OperationPopover;

import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import DialogActions from '@mui/material/DialogActions';
import DialogContentText from '@mui/material/DialogContentText';
import { MoreVert } from '@mui/icons-material';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import { connectorDeletionMutation, connectorResetStateMutation, connectorWorkDeleteMutation } from '@components/data/connectors/Connector';
import canDeleteConnector from '@components/data/connectors/utils/canDeleteConnector';
import { Connector_connector$data } from '@components/data/connectors/__generated__/Connector_connector.graphql';
import { FEED_MUTATIONS } from '@components/integrations/feeds/feedMutations';
import { DeployedIntegrationItem } from '@components/integrations/deployed/useDeployedIntegrations';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import useGranted, { INGESTION_SETINGESTIONS, MODULES_MODMANAGE } from '../../../../utils/hooks/useGranted';
import stopEvent from '../../../../utils/domEvent';

interface DeployedIntegrationPopoverProps {
  item: DeployedIntegrationItem;
  onChange: () => void;
}

// Per-card actions: start/stop and delete for built-in feeds; reset state,
// clear works and delete for connectors (same set as the detail page).
const DeployedIntegrationPopover = ({ item, onChange }: DeployedIntegrationPopoverProps) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [displayReset, setDisplayReset] = useState(false);
  const [displayClearWorks, setDisplayClearWorks] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const isGrantedToModules = useGranted([MODULES_MODMANAGE]);
  const isGrantedToIngestion = useGranted([INGESTION_SETINGESTIONS]);

  const isConnector = item.kind === 'connector';
  const feedConfig = !isConnector ? FEED_MUTATIONS[item.kind] : null;

  const handleOpen = (event: React.MouseEvent<HTMLElement>) => {
    stopEvent(event);
    setAnchorEl(event.currentTarget);
  };
  const handleClose = (event?: React.SyntheticEvent) => {
    if (event) {
      event.preventDefault();
      event.stopPropagation();
    }
    setAnchorEl(null);
  };

  const handleToggleRunning = (event: React.MouseEvent) => {
    handleClose(event);
    if (!feedConfig) return;
    const nextRunning = !item.running;
    setSubmitting(true);
    if (feedConfig.toggleMutation && feedConfig.toggleField) {
      commitMutation({
        mutation: feedConfig.toggleMutation,
        variables: {
          id: item.id,
          input: { key: feedConfig.toggleField, value: [String(nextRunning)] },
        },
        onCompleted: () => {
          setSubmitting(false);
          onChange();
        },
        onError: () => setSubmitting(false),
        updater: undefined,
        optimisticResponse: undefined,
        optimisticUpdater: undefined,
        setSubmitting: undefined,
      });
    } else {
      const mutation = nextRunning ? feedConfig.startMutation : feedConfig.stopMutation;
      if (!mutation) return;
      commitMutation({
        mutation,
        variables: { id: item.id },
        onCompleted: () => {
          setSubmitting(false);
          onChange();
        },
        onError: () => setSubmitting(false),
        updater: undefined,
        optimisticResponse: undefined,
        optimisticUpdater: undefined,
        setSubmitting: undefined,
      });
    }
  };

  const submitClearWorks = () => {
    setSubmitting(true);
    commitMutation({
      mutation: connectorWorkDeleteMutation,
      variables: { connectorId: item.id },
      onCompleted: () => {
        // Same untranslated notification as the connector detail popover.
        MESSAGING$.notifySuccess('The connector works have been cleared');
        setSubmitting(false);
        setDisplayClearWorks(false);
        onChange();
      },
      onError: () => setSubmitting(false),
      updater: undefined,
      optimisticResponse: undefined,
      optimisticUpdater: undefined,
      setSubmitting: undefined,
    });
  };

  const submitDelete = () => {
    setSubmitting(true);
    if (isConnector) {
      commitMutation({
        mutation: connectorDeletionMutation,
        variables: { id: item.id },
        onCompleted: () => {
          setSubmitting(false);
          setDisplayDelete(false);
          onChange();
        },
        onError: () => setSubmitting(false),
        updater: undefined,
        optimisticResponse: undefined,
        optimisticUpdater: undefined,
        setSubmitting: undefined,
      });
    } else if (feedConfig) {
      commitMutation({
        mutation: feedConfig.deleteMutation,
        variables: { id: item.id },
        onCompleted: () => {
          setSubmitting(false);
          setDisplayDelete(false);
          onChange();
        },
        onError: () => setSubmitting(false),
        updater: undefined,
        optimisticResponse: undefined,
        optimisticUpdater: undefined,
        setSubmitting: undefined,
      });
    }
  };

  const submitReset = () => {
    setSubmitting(true);
    commitMutation({
      mutation: connectorResetStateMutation,
      variables: { id: item.id },
      onCompleted: () => {
        MESSAGING$.notifySuccess(t_i18n('The connector state has been reset'));
        setSubmitting(false);
        setDisplayReset(false);
        onChange();
      },
      onError: () => setSubmitting(false),
      updater: undefined,
      optimisticResponse: undefined,
      optimisticUpdater: undefined,
      setSubmitting: undefined,
    });
  };

  const canManageConnector = isConnector
    && isGrantedToModules
    && canDeleteConnector(item.connector as unknown as Connector_connector$data);
  const canManageFeed = !isConnector && isGrantedToIngestion;

  // Opening the card already navigates to the details: without any granted
  // action, the popover has nothing to offer.
  if (!canManageConnector && !canManageFeed) {
    return null;
  }

  return (
    <div onClick={stopEvent}>
      <IconButton
        aria-label={t_i18n('Open menu')}
        onClick={handleOpen}
        aria-haspopup="true"
        color="primary"
        size="small"
      >
        <MoreVert fontSize="small" />
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={() => setAnchorEl(null)}
      >
        {canManageFeed && (
          <MenuItem onClick={handleToggleRunning} disabled={submitting}>
            {item.running ? t_i18n('Stop') : t_i18n('Start')}
          </MenuItem>
        )}
        {canManageConnector && (
          <MenuItem
            onClick={(event) => {
              handleClose(event);
              setDisplayReset(true);
            }}
          >
            {t_i18n('Reset the connector state')}
          </MenuItem>
        )}
        {canManageConnector && (
          <MenuItem
            onClick={(event) => {
              handleClose(event);
              setDisplayClearWorks(true);
            }}
          >
            {t_i18n('Clear all works')}
          </MenuItem>
        )}
        {(canManageConnector || canManageFeed) && (
          <MenuItem
            onClick={(event) => {
              handleClose(event);
              setDisplayDelete(true);
            }}
          >
            {t_i18n('Delete')}
          </MenuItem>
        )}
      </Menu>

      <Dialog
        open={displayClearWorks}
        onClose={() => setDisplayClearWorks(false)}
        size="small"
        title={t_i18n('Are you sure?')}
      >
        <DialogContentText>
          {t_i18n('Do you want to clear the works of this connector?')}
        </DialogContentText>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={() => setDisplayClearWorks(false)}
            disabled={submitting}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button onClick={submitClearWorks} disabled={submitting}>
            {t_i18n('Confirm')}
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog
        open={displayDelete}
        onClose={() => setDisplayDelete(false)}
        title={t_i18n('Are you sure?')}
      >
        <DialogContentText>
          {isConnector
            ? t_i18n('Do you want to delete this connector?')
            : t_i18n('Do you want to delete this integration instance?')}
        </DialogContentText>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={() => setDisplayDelete(false)}
            disabled={submitting}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button onClick={submitDelete} disabled={submitting}>
            {t_i18n('Confirm')}
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog
        open={displayReset}
        onClose={() => setDisplayReset(false)}
        title={t_i18n('Are you sure?')}
      >
        <DialogContentText>
          {t_i18n('Do you want to reset the state and purge messages queue of this connector?')}
        </DialogContentText>
        <DialogContentText>
          {t_i18n('Number of messages: ') + (item.messagesCount ?? 0)}
        </DialogContentText>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={() => setDisplayReset(false)}
            disabled={submitting}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button onClick={submitReset} disabled={submitting}>
            {t_i18n('Confirm')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default DeployedIntegrationPopover;

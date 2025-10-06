import MoreVert from '@mui/icons-material/MoreVert';
import React, { useState } from 'react';
import { PopoverProps } from '@mui/material/Popover';
import { connectorDeletionMutation, connectorResetStateMutation, connectorWorkDeleteMutation } from '@private/components/data/connectors/Connector';
import { Connector_connector$data } from '@private/components/data/connectors/__generated__/Connector_connector.graphql';
import { useNavigate } from 'react-router-dom';
import ManagedConnectorEdition from '@private/components/data/connectors/ManagedConnectorEdition';
import { useTheme } from '@mui/styles';
import DangerZoneChip from '@private/components/common/danger_zone/DangerZoneChip';
import DangerZoneBlock from '@private/components/common/danger_zone/DangerZoneBlock';
import { Alert, Button, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, Menu, MenuItem, ToggleButton } from '@components';
import type { Theme } from '../../../../components/Theme';
import useSensitiveModifications from '../../../../utils/hooks/useSensitiveModifications';
import { MESSAGING$ } from '../../../../relay/environment';
import Transition from '../../../../components/Transition';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';
import { useFormatter } from '../../../../components/i18n';
import useDeletion from '../../../../utils/hooks/useDeletion';
import stopEvent from '../../../../utils/domEvent';

interface ConnectorPopoverProps {
  connector: Connector_connector$data;
  onRefreshData?: () => void;
}

const ConnectorPopover = ({ connector, onRefreshData }: ConnectorPopoverProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);
  const [editionOpen, setEditionOpen] = useState(false);
  const [displayClearWorks, setDisplayClearWorks] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [displayResetState, setDisplayResetState] = useState(false);
  const [resetting, setResetting] = useState(false);

  const { isSensitive } = useSensitiveModifications('connector_reset');

  const [commitDeleteConnector] = useApiMutation(connectorDeletionMutation);
  const [commitClearWorks] = useApiMutation(connectorWorkDeleteMutation);
  const [commitResetState] = useApiMutation(connectorResetStateMutation);

  const handleOpen = (event: React.MouseEvent<HTMLElement>) => {
    stopEvent(event);
    setAnchorEl(event.currentTarget);

    onRefreshData?.();
  };

  const handleClose = (event: React.MouseEvent<HTMLElement>) => {
    stopEvent(event);
    setAnchorEl(null);
  };

  const handleOpenEdit = () => {
    setAnchorEl(null);
    setEditionOpen(true);
  };

  const handleOpenClearWorks = () => {
    setAnchorEl(null);
    setDisplayClearWorks(true);
  };

  const handleCloseClearWorks = () => {
    setDisplayClearWorks(false);
  };

  const handleOpenResetState = () => {
    setAnchorEl(null);
    setDisplayResetState(true);
  };

  const handleCloseResetState = () => {
    setDisplayResetState(false);
  };

  const submitClearWorks = () => {
    setClearing(true);
    commitClearWorks({
      variables: {
        connectorId: connector.id,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('The connector works have been cleared');
        setClearing(false);
        setDisplayClearWorks(false);
      },
    });
  };

  const submitResetState = () => {
    setResetting(true);
    commitResetState({
      variables: {
        id: connector.id,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('The connector state has been reset and messages queue has been purged');
        setResetting(false);
        setDisplayResetState(false);
      },
    });
  };

  const deletion = useDeletion({ handleClose: () => setAnchorEl(null) });
  const { setDeleting, handleOpenDelete, handleCloseDelete } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commitDeleteConnector({
      variables: {
        id: connector.id,
      },
      onCompleted: () => {
        handleCloseDelete();
        navigate('/dashboard/data/ingestion/connectors');
      },
    });
  };

  return (
    <>
      <ToggleButton
        onClick={handleOpen}
        aria-haspopup="true"
        value="popover"
        color="primary"
        size={'small'}
      >
        <MoreVert fontSize="small" color="primary" />
      </ToggleButton>

      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
      >
        {connector.is_managed && (
          <MenuItem onClick={handleOpenEdit}>{t_i18n('Update')}</MenuItem>
        )}
        {isSensitive ? (
          <DangerZoneBlock
            type="connector_reset"
            sx={{ title: { display: 'none' } }}
            component={
              <MenuItem onClick={handleOpenResetState} sx={{ color: theme.palette.dangerZone.main }}>
                {t_i18n('Reset')}<DangerZoneChip style={{ marginLeft: 8 }} />
              </MenuItem>
            }
          />
        ) : (
          <MenuItem onClick={handleOpenResetState}>{t_i18n('Reset the connector state')}</MenuItem>
        )}
        <MenuItem onClick={handleOpenClearWorks}>{t_i18n('Clear all works')}</MenuItem>
        <MenuItem onClick={handleOpenDelete} disabled={!!connector.active || !!connector.built_in}>{t_i18n('Delete')}</MenuItem>
      </Menu>

      {
        connector.is_managed && connector.manager_contract_definition && (
          <ManagedConnectorEdition
            open={editionOpen}
            onClose={() => setEditionOpen(false)}
            connector={connector}
          />
        )
      }

      <Dialog
        slotProps={{ paper: { elevation: 1 } }}
        open={displayClearWorks}
        keepMounted={true}
        slots={{ transition: Transition }}
        onClose={handleCloseClearWorks}
      >
        <DialogTitle>
          {t_i18n('Are you sure?')}
        </DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to clear the works of this connector?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={handleCloseClearWorks}
            disabled={clearing}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitClearWorks}
            color="secondary"
            disabled={clearing}
          >
            {t_i18n('Confirm')}
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog
        slotProps={{ paper: { elevation: 1 } }}
        open={displayResetState}
        keepMounted={true}
        slots={{ transition: Transition }}
        onClose={handleCloseResetState}
      >
        <DialogTitle>
          {t_i18n('Are you sure?')}
        </DialogTitle>
        <DialogContent>
          <DialogContentText component="div">
            <Alert
              severity={isSensitive ? 'warning' : 'info'}
              variant="outlined"
              color={isSensitive ? 'dangerZone' : undefined}
              style={isSensitive ? {
                borderColor: theme.palette.dangerZone.main,
              } : {}}
            >
              <div>
                {t_i18n('Do you want to reset the state and purge messages queue of this connector?')}
                <br />
                {t_i18n('Number of messages: ') + connector.connector_queue_details.messages_number}
              </div>
            </Alert>
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={handleCloseResetState}
            disabled={resetting}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitResetState}
            color={isSensitive ? 'error' : 'secondary'}
            disabled={resetting}
          >
            {t_i18n('Confirm')}
          </Button>
        </DialogActions>
      </Dialog>

      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this connector?')}
      />

    </>
  );
};

export default ConnectorPopover;

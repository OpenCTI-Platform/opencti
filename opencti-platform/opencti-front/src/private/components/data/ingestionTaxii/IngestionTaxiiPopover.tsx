import React, { Dispatch, FunctionComponent, Suspense, useState } from 'react';
import { graphql, useQueryLoader } from 'react-relay';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import MoreVert from '@mui/icons-material/MoreVert';
import { IngestionTaxiiLinesPaginationQuery$variables } from '@components/data/ingestionTaxii/__generated__/IngestionTaxiiLinesPaginationQuery.graphql';
import { PopoverProps } from '@mui/material/Popover';
import IngestionTaxiiEditionContainer, { ingestionTaxiiEditionContainerQuery } from '@components/data/ingestionTaxii/IngestionTaxiiEditionContainer';
import { IngestionTaxiiEditionContainerQuery } from '@components/data/ingestionTaxii/__generated__/IngestionTaxiiEditionContainerQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { ingestionTaxiiMutationFieldPatch } from './IngestionTaxiiEdition';
import { deleteNode } from '../../../../utils/store';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Transition from '../../../../components/Transition';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';

const ingestionTaxiiPopoverDeletionMutation = graphql`
  mutation IngestionTaxiiPopoverDeletionMutation($id: ID!) {
    ingestionTaxiiDelete(id: $id)
  }
`;

const ingestionTaxiiPopoverResetStateMutation = graphql`
    mutation IngestionTaxiiPopoverResetStateMutation($id: ID!) {
        ingestionTaxiiResetState(id: $id) {
            ...IngestionTaxiiLine_node
        }
    }
`;

interface IngestionTaxiiPopoverProps {
  ingestionTaxiiId: string;
  running?: boolean | null;
  paginationOptions?: IngestionTaxiiLinesPaginationQuery$variables | null | undefined;
  setStateValue: Dispatch<string>;
}

const IngestionTaxiiPopover: FunctionComponent<IngestionTaxiiPopoverProps> = ({
  ingestionTaxiiId,
  running,
  paginationOptions,
  setStateValue,
}) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);
  const [displayStart, setDisplayStart] = useState(false);
  const [starting, setStarting] = useState(false);
  const [displayStop, setDisplayStop] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [displayResetState, setDisplayResetState] = useState(false);
  const [resettingState, setResettingState] = useState(false);

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleOpen = (event: React.SyntheticEvent) => {
    setAnchorEl(event.currentTarget);
  };

  // -- Edition --
  const [queryRef, loadQuery] = useQueryLoader<IngestionTaxiiEditionContainerQuery>(ingestionTaxiiEditionContainerQuery);
  const [displayUpdate, setDisplayUpdate] = useState(false);
  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    loadQuery({ id: ingestionTaxiiId });
    handleClose();
  };

  const handleOpenResetState = () => {
    setDisplayResetState(true);
    handleClose();
  };

  const handleCloseResetState = () => {
    setDisplayResetState(false);
  };

  const handleOpenStart = () => {
    setDisplayStart(true);
    handleClose();
  };

  const handleCloseStart = () => {
    setDisplayStart(false);
  };

  const handleOpenStop = () => {
    setDisplayStop(true);
    handleClose();
  };

  const handleCloseStop = () => {
    setDisplayStop(false);
  };

  const [commitDelete] = useApiMutation(ingestionTaxiiPopoverDeletionMutation);
  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleOpenDelete, handleCloseDelete } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commitDelete({
      variables: {
        id: ingestionTaxiiId,
      },
      updater: (store) => {
        deleteNode(
          store,
          'Pagination_ingestionTaxiis',
          paginationOptions,
          ingestionTaxiiId,
        );
      },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
      },
    });
  };

  const [commitResetState] = useApiMutation(ingestionTaxiiPopoverResetStateMutation);
  const submitResetState = () => {
    setResettingState(true);
    commitResetState({
      variables: {
        id: ingestionTaxiiId,
      },
      onCompleted: () => {
        setResettingState(false);
        setStateValue('-');
        handleCloseResetState();
      },
    });
  };

  const [commitStart] = useApiMutation(ingestionTaxiiMutationFieldPatch);
  const submitStart = () => {
    setStarting(true);
    commitStart({
      variables: {
        id: ingestionTaxiiId,
        input: { key: 'ingestion_running', value: ['true'] },
      },
      onCompleted: () => {
        setStarting(false);
        handleCloseStart();
      },
    });
  };

  const [commitStop] = useApiMutation(ingestionTaxiiMutationFieldPatch);
  const submitStop = () => {
    setStopping(true);
    commitStop({
      variables: {
        id: ingestionTaxiiId,
        input: { key: 'ingestion_running', value: ['false'] },
      },
      onCompleted: () => {
        setStopping(false);
        handleCloseStop();
      },
    });
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
        {!running && (
          <MenuItem onClick={handleOpenStart}>
            {t_i18n('Start')}
          </MenuItem>
        )}
        {running && (
          <MenuItem onClick={handleOpenStop}>
            {t_i18n('Stop')}
          </MenuItem>
        )}
        <MenuItem onClick={handleOpenUpdate}>
          {t_i18n('Update')}
        </MenuItem>
        <MenuItem onClick={handleOpenDelete}>
          {t_i18n('Delete')}
        </MenuItem>
        <MenuItem onClick={handleOpenResetState}>
          {t_i18n('Reset state')}
        </MenuItem>
      </Menu>
      {displayUpdate && queryRef && (
        <Suspense>
          <IngestionTaxiiEditionContainer
            queryRef={queryRef}
            handleClose={() => setDisplayUpdate(false)}
            open={displayUpdate}
          />
        </Suspense>
      )}
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this TAXII ingester?')}
      />
      <Dialog
        slotProps={{ paper: { elevation: 1 } }}
        open={displayResetState}
        keepMounted={true}
        slots={{ transition: Transition }}
        onClose={handleCloseResetState}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to reset the state of this TAXII ingester? It will restart ingestion from the beginning.')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={handleCloseResetState}
            disabled={resettingState}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitResetState}
            disabled={resettingState}
          >
            {t_i18n('Reset state')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        slotProps={{ paper: { elevation: 1 } }}
        open={displayStart}
        keepMounted={true}
        slots={{ transition: Transition }}
        onClose={handleCloseStart}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to start this TAXII ingester?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={handleCloseStart}
            disabled={starting}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitStart}
            disabled={starting}
          >
            {t_i18n('Start')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        slotProps={{ paper: { elevation: 1 } }}
        open={displayStop}
        keepMounted={true}
        slots={{ transition: Transition }}
        onClose={handleCloseStop}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to stop this TAXII ingester?')}
          </DialogContentText>
        </DialogContent>
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
          >
            {t_i18n('Stop')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default IngestionTaxiiPopover;

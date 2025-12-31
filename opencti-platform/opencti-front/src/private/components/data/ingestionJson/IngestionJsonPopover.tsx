import { graphql, useQueryLoader } from 'react-relay';
import React, { FunctionComponent, useState } from 'react';
import { PopoverProps } from '@mui/material/Popover';
import IconButton from '@common/button/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import Button from '@common/button/Button';
import DialogActions from '@mui/material/DialogActions';
import IngestionJsonEditionContainer, { ingestionJsonEditionContainerQuery } from '@components/data/ingestionJson/IngestionJsonEditionContainer';
import { IngestionJsonCreationContainer } from '@components/data/ingestionJson/IngestionJsonCreation';
import { IngestionJsonLinesPaginationQuery$variables } from '@components/data/ingestionJson/__generated__/IngestionJsonLinesPaginationQuery.graphql';
import { IngestionJsonEditionContainerQuery } from '@components/data/ingestionJson/__generated__/IngestionJsonEditionContainerQuery.graphql';
import { deleteNode } from '../../../../utils/store';
import { useFormatter } from '../../../../components/i18n';
import Transition from '../../../../components/Transition';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

export const ingestionJsonPopoverEditionPatch = graphql`
  mutation IngestionJsonPopoverPatchMutation($id: ID!, $input: [EditInput!]!) {
    ingestionJsonFieldPatch(id: $id, input: $input) {
      ...IngestionJsonEditionFragment_ingestionJson
    }
  }
`;

const ingestionJsonPopoverDeletionMutation = graphql`
  mutation IngestionJsonPopoverDeletionMutation($id: ID!) {
    ingestionJsonDelete(id: $id)
  }
`;

const ingestionJsonPopoverResetStateMutation = graphql`
    mutation IngestionJsonPopoverResetStateMutation($id: ID!) {
        ingestionJsonResetState(id: $id) {
            ...IngestionJsonLine_node
        }
    }
`;

interface IngestionJsonPopoverProps {
  ingestionJsonId: string;
  running?: boolean | null;
  paginationOptions?: IngestionJsonLinesPaginationQuery$variables | null | undefined;
}

const IngestionJsonPopover: FunctionComponent<IngestionJsonPopoverProps> = ({
  ingestionJsonId,
  paginationOptions,
  running,
}) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);
  const [displayStart, setDisplayStart] = useState(false);
  const [starting, setStarting] = useState(false);
  const [displayStop, setDisplayStop] = useState(false);
  const [stopping, setStopping] = useState(false);
  const handleOpen = (event: React.MouseEvent) => setAnchorEl(event.currentTarget);
  const handleClose = () => setAnchorEl(null);

  // -- Edition --
  const [queryRef, loadQuery] = useQueryLoader<IngestionJsonEditionContainerQuery>(ingestionJsonEditionContainerQuery);
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);
  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    loadQuery({ id: ingestionJsonId });
    handleClose();
  };

  // -- Duplicate --
  const [displayDuplicate, setDisplayDuplicate] = useState<boolean>(false);
  const handleOpenDuplicate = () => {
    setDisplayDuplicate(true);
    loadQuery({ id: ingestionJsonId });
    handleClose();
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

  // -- Deletion --
  const [displayDelete, setDisplayDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [commitDelete] = useApiMutation(ingestionJsonPopoverDeletionMutation);
  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };

  const handleCloseDelete = () => {
    setDisplayDelete(false);
  };
  const submitDelete = () => {
    setDeleting(true);
    commitDelete({
      variables: {
        id: ingestionJsonId,
      },
      updater: (store) => {
        deleteNode(store, 'Pagination_ingestionJsons', paginationOptions, ingestionJsonId);
      },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
      },
    });
  };
  // -- Reset state --
  const [displayResetState, setDisplayResetState] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [commitResetState] = useApiMutation(ingestionJsonPopoverResetStateMutation);
  const handleOpenResetState = () => {
    setDisplayResetState(true);
    handleClose();
  };

  const handleCloseResetState = () => {
    setDisplayResetState(false);
    setResetting(false);
  };
  const submitResetState = () => {
    setResetting(true);
    commitResetState({
      variables: {
        id: ingestionJsonId,
      },
      onCompleted: () => {
        setResetting(false);
        handleCloseResetState();
      },
    });
    handleCloseResetState();
  };

  // -- Running --
  const [commitRunning] = useApiMutation(ingestionJsonPopoverEditionPatch);
  const submitStart = () => {
    setStarting(true);
    commitRunning({
      variables: {
        id: ingestionJsonId,
        input: { key: 'ingestion_running', value: ['true'] },
      },
      onCompleted: () => {
        setStarting(false);
        handleCloseStart();
      },
    });
  };

  const submitStop = () => {
    setStopping(true);
    commitRunning({
      variables: {
        id: ingestionJsonId,
        input: { key: 'ingestion_running', value: ['false'] },
      },
      onCompleted: () => {
        setStopping(false);
        handleCloseStop();
      },
    });
  };
  return (
    <>
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
          <MenuItem onClick={handleOpenDuplicate}>
            {t_i18n('Duplicate')}
          </MenuItem>
          <MenuItem onClick={handleOpenResetState}>
            {t_i18n('Reset state')}
          </MenuItem>
          <MenuItem onClick={handleOpenDelete}>
            {t_i18n('Delete')}
          </MenuItem>
        </Menu>
        {queryRef && (
          <React.Suspense>
            <>
              <IngestionJsonEditionContainer
                queryRef={queryRef}
                handleClose={() => setDisplayUpdate(false)}
                open={displayUpdate}
              />
              <IngestionJsonCreationContainer
                queryRef={queryRef}
                handleClose={() => setDisplayDuplicate(false)}
                open={displayDuplicate}
                paginationOptions={paginationOptions}
                isDuplicated={true}
              />
            </>
          </React.Suspense>
        )}
        <Dialog
          slotProps={{ paper: { elevation: 1 } }}
          open={displayDelete}
          keepMounted
          slots={{ transition: Transition }}
          onClose={handleCloseDelete}
        >
          <DialogContent>
            <DialogContentText>
              {t_i18n('Do you want to delete this JSON feed?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              variant="secondary"
              onClick={handleCloseDelete}
              disabled={deleting}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={submitDelete}
              disabled={deleting}
            >
              {t_i18n('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
        <Dialog
          slotProps={{ paper: { elevation: 1 } }}
          open={displayResetState}
          keepMounted
          slots={{ transition: Transition }}
          onClose={handleCloseResetState}
        >
          <DialogContent>
            <DialogContentText>
              {t_i18n('Do you want to reset the state of this JSON feed?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              variant="secondary"
              onClick={handleCloseResetState}
              disabled={resetting}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={submitResetState}
              disabled={resetting}
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
              {t_i18n('Do you want to start this JSON feed?')}
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
              {t_i18n('Do you want to stop this JSON feed?')}
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
    </>
  );
};

export default IngestionJsonPopover;

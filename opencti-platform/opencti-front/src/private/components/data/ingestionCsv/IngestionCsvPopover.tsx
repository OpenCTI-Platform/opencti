import { graphql, useQueryLoader } from 'react-relay';
import React, { FunctionComponent, useState } from 'react';
import { PopoverProps } from '@mui/material/Popover';
import IconButton from '@mui/material/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import { Button } from '@mui/material';
import DialogActions from '@mui/material/DialogActions';
import IngestionCsvEditionContainer, { ingestionCsvEditionContainerQuery } from '@components/data/ingestionCsv/IngestionCsvEditionContainer';
import { ingestionCsvEditionPatch } from '@components/data/ingestionCsv/IngestionCsvEdition';
import { IngestionCsvLinesPaginationQuery$variables } from '@components/data/ingestionCsv/__generated__/IngestionCsvLinesPaginationQuery.graphql';
import { IngestionCsvEditionContainerQuery } from '@components/data/ingestionCsv/__generated__/IngestionCsvEditionContainerQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { deleteNode } from '../../../../utils/store';
import { useFormatter } from '../../../../components/i18n';
import Transition from '../../../../components/Transition';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const ingestionCsvPopoverDeletionMutation = graphql`
  mutation IngestionCsvPopoverDeletionMutation($id: ID!) {
    ingestionCsvDelete(id: $id)
  }
`;

interface IngestionCsvPopoverProps {
  ingestionCsvId: string;
  running?: boolean | null;
  paginationOptions?: IngestionCsvLinesPaginationQuery$variables;
}

const IngestionCsvPopover: FunctionComponent<IngestionCsvPopoverProps> = ({
  ingestionCsvId,
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
  const [queryRef, loadQuery] = useQueryLoader<IngestionCsvEditionContainerQuery>(ingestionCsvEditionContainerQuery);
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);
  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    loadQuery({ id: ingestionCsvId });
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
  const [commit] = useApiMutation(ingestionCsvPopoverDeletionMutation);
  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };

  const handleCloseDelete = () => {
    setDisplayDelete(false);
  };
  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id: ingestionCsvId,
      },
      updater: (store) => {
        deleteNode(store, 'Pagination_ingestionCsvs', paginationOptions, ingestionCsvId);
      },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
      },
    });
  };

  // -- Running --
  const [commitRunning] = useApiMutation(ingestionCsvEditionPatch);
  const submitStart = () => {
    setStarting(true);
    commitRunning({
      variables: {
        id: ingestionCsvId,
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
        id: ingestionCsvId,
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
          size="large"
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
        </Menu>
        {queryRef && (
          <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <IngestionCsvEditionContainer
              queryRef={queryRef}
              handleClose={() => setDisplayUpdate(false)}
              open={displayUpdate}
            />
          </React.Suspense>
        )}
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={displayDelete}
          keepMounted
          TransitionComponent={Transition}
          onClose={handleCloseDelete}
        >
          <DialogContent>
            <DialogContentText>
              {t_i18n('Do you want to delete this CSV ingester?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={handleCloseDelete}
              disabled={deleting}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              color="secondary"
              onClick={submitDelete}
              disabled={deleting}
            >
              {t_i18n('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={displayStart}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={handleCloseStart}
        >
          <DialogContent>
            <DialogContentText>
              {t_i18n('Do you want to start this CSV ingester?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={handleCloseStart}
              disabled={starting}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={submitStart}
              color="secondary"
              disabled={starting}
            >
              {t_i18n('Start')}
            </Button>
          </DialogActions>
        </Dialog>
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={displayStop}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={handleCloseStop}
        >
          <DialogContent>
            <DialogContentText>
              {t_i18n('Do you want to stop this CSV ingester?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={handleCloseStop}
              disabled={stopping}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={submitStop}
              color="secondary"
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

export default IngestionCsvPopover;

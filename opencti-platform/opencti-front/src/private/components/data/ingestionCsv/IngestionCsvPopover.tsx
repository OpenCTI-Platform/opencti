import { graphql, useQueryLoader } from 'react-relay';
import React, { Dispatch, FunctionComponent, UIEvent, useState } from 'react';
import { PopoverProps } from '@mui/material/Popover';
import MoreVert from '@mui/icons-material/MoreVert';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import DialogActions from '@mui/material/DialogActions';
import IngestionCsvEditionContainer, { ingestionCsvEditionContainerQuery } from '@components/data/ingestionCsv/IngestionCsvEditionContainer';
import { ingestionCsvEditionPatch } from '@components/data/ingestionCsv/IngestionCsvEdition';
import { IngestionCsvLinesPaginationQuery$variables } from '@components/data/ingestionCsv/__generated__/IngestionCsvLinesPaginationQuery.graphql';
import { IngestionCsvEditionContainerQuery } from '@components/data/ingestionCsv/__generated__/IngestionCsvEditionContainerQuery.graphql';
import { IngestionCsvCreationContainer } from '@components/data/ingestionCsv/IngestionCsvCreation';
import DialogTitle from '@mui/material/DialogTitle';
import fileDownload from 'js-file-download';
import { deleteNode } from '../../../../utils/store';
import { useFormatter } from '../../../../components/i18n';
import Transition from '../../../../components/Transition';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';
import stopEvent from '../../../../utils/domEvent';
import { fetchQuery } from '../../../../relay/environment';
import { IngestionCsvPopoverExportQuery$data } from './__generated__/IngestionCsvPopoverExportQuery.graphql';

const ingestionCsvPopoverDeletionMutation = graphql`
  mutation IngestionCsvPopoverDeletionMutation($id: ID!) {
    ingestionCsvDelete(id: $id)
  }
`;

const ingestionCsvPopoverResetStateMutation = graphql`
    mutation IngestionCsvPopoverResetStateMutation($id: ID!) {
        ingestionCsvResetState(id: $id) {
            ...IngestionCsvLine_node
        }
    }
`;

const ingestionCsvPopoverExportQuery = graphql`
  query IngestionCsvPopoverExportQuery($id: String!) {
    ingestionCsv(id: $id) {
      name
      toConfigurationExport
    }
  }
`;
interface IngestionCsvPopoverProps {
  ingestionCsvId: string;
  running?: boolean | null;
  paginationOptions?: IngestionCsvLinesPaginationQuery$variables | null | undefined;
  setStateHash: Dispatch<string>;
}

const IngestionCsvPopover: FunctionComponent<IngestionCsvPopoverProps> = ({
  ingestionCsvId,
  paginationOptions,
  running,
  setStateHash,
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

  // -- Duplicate --
  const [displayDuplicate, setDisplayDuplicate] = useState<boolean>(false);
  const handleOpenDuplicate = () => {
    setDisplayDuplicate(true);
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
  const [commitDelete] = useApiMutation(ingestionCsvPopoverDeletionMutation);
  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleOpenDelete, handleCloseDelete } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commitDelete({
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
  // -- Reset state --
  const [displayResetState, setDisplayResetState] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [commitResetState] = useApiMutation(ingestionCsvPopoverResetStateMutation);
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
        id: ingestionCsvId,
      },
      onCompleted: () => {
        setResetting(false);
        setStateHash('-'); // would be great to update relay store instead, I haven't find how.
        handleCloseResetState();
      },
    });
    handleCloseResetState();
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

  // -- Export --

  const exportCsvFeed = async () => {
    const { ingestionCsv } = await fetchQuery(
      ingestionCsvPopoverExportQuery,
      { id: ingestionCsvId },
    ).toPromise() as IngestionCsvPopoverExportQuery$data;

    if (ingestionCsv) {
      const blob = new Blob([ingestionCsv.toConfigurationExport], { type: 'text/json' });
      const [day, month, year] = new Date().toLocaleDateString('fr-FR').split('/');
      const fileName = `${year}${month}${day}_csvFeed_${ingestionCsv.name}.json`;
      fileDownload(blob, fileName);
    }
  };
  const handleExport = async (e: UIEvent) => {
    stopEvent(e);
    setAnchorEl(undefined);
    await exportCsvFeed();
  };
  return (
    <>
      <div style={{ margin: 0 }}>
        <IconButton
          onClick={handleOpen}
          aria-haspopup="true"
          style={{ marginTop: 3 }}
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
          <MenuItem onClick={handleExport}>
            {t_i18n('Export')}
          </MenuItem>

        </Menu>
        {queryRef && (
          <React.Suspense>
            <>
              <IngestionCsvEditionContainer
                queryRef={queryRef}
                handleClose={() => setDisplayUpdate(false)}
                open={displayUpdate}
              />
              <IngestionCsvCreationContainer
                queryRef={queryRef}
                handleClose={() => setDisplayDuplicate(false)}
                open={displayDuplicate}
                triggerButton={false}
                paginationOptions={paginationOptions}
                drawerSettings={{
                  title: t_i18n('Duplicate a CSV Feed'),
                  button: t_i18n('Duplicate'),
                }}
              />
            </>
          </React.Suspense>
        )}
        <DeleteDialog
          deletion={deletion}
          submitDelete={submitDelete}
          message={t_i18n('Do you want to delete this CSV Feed?')}
        />
        <Dialog
          slotProps={{ paper: { elevation: 1 } }}
          open={displayResetState}
          keepMounted
          slots={{ transition: Transition }}
          onClose={handleCloseResetState}
        >
          <DialogTitle>
            {t_i18n('Are you sure?')}
          </DialogTitle>
          <DialogContent>
            <DialogContentText>
              {t_i18n('Do you want to reset the state of this CSV Feed?')}
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
              {t_i18n('Confirm')}
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
          <DialogTitle>
            {t_i18n('Are you sure?')}
          </DialogTitle>
          <DialogContent>
            <DialogContentText>
              {t_i18n('Do you want to start this CSV Feed?')}
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
              {t_i18n('Confirm')}
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
          <DialogTitle>
            {t_i18n('Are you sure?')}
          </DialogTitle>
          <DialogContent>
            <DialogContentText>
              {t_i18n('Do you want to stop this CSV Feed?')}
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
              {t_i18n('Confirm')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    </>
  );
};

export default IngestionCsvPopover;

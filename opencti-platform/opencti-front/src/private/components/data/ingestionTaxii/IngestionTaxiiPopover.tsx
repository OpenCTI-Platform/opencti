import React, { Dispatch, FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import MoreVert from '@mui/icons-material/MoreVert';
import { IngestionTaxiiLinesPaginationQuery$variables } from '@components/data/ingestionTaxii/__generated__/IngestionTaxiiLinesPaginationQuery.graphql';
import { IngestionTaxiiPopoverEditionQuery$data } from '@components/data/ingestionTaxii/__generated__/IngestionTaxiiPopoverEditionQuery.graphql';
import { PopoverProps } from '@mui/material/Popover';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import IngestionTaxiiEdition, { ingestionTaxiiMutationFieldPatch } from './IngestionTaxiiEdition';
import { deleteNode } from '../../../../utils/store';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Transition from '../../../../components/Transition';

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

const ingestionTaxiiEditionQuery = graphql`
  query IngestionTaxiiPopoverEditionQuery($id: String!) {
    ingestionTaxii(id: $id) {
      id
      name
      description
      uri
      version
      ingestion_running
      ...IngestionTaxiiEdition_ingestionTaxii
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
  const [displayUpdate, setDisplayUpdate] = useState(false);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
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

  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    handleClose();
  };

  const handleCloseUpdate = () => {
    setDisplayUpdate(false);
  };

  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };

  const handleCloseDelete = () => {
    setDisplayDelete(false);
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
    <div style={{ margin: 0 }} >
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
        style={{ marginTop: 3 }}
        size="large"
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
      <QueryRenderer
        query={ingestionTaxiiEditionQuery}
        variables={{ id: ingestionTaxiiId }}
        render={({ props }: { props: IngestionTaxiiPopoverEditionQuery$data }) => {
          if (props) {
            return (
              <IngestionTaxiiEdition
                ingestionTaxii={props.ingestionTaxii}
                handleClose={handleCloseUpdate}
                open={displayUpdate}
              />
            );
          }
          return <div />;
        }}
      />
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayDelete}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this TAXII ingester?')}
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
        open={displayResetState}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseResetState}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to reset the state of this TAXII ingester? It will restart ingestion from the beginning.')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={handleCloseResetState}
            disabled={resettingState}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            color="secondary"
            onClick={submitResetState}
            disabled={resettingState}
          >
            {t_i18n('Reset state')}
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
            {t_i18n('Do you want to start this TAXII ingester?')}
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
            {t_i18n('Do you want to stop this TAXII ingester?')}
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
  );
};

export default IngestionTaxiiPopover;

import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import MoreVert from '@mui/icons-material/MoreVert';

import { PopoverProps } from '@mui/material/Popover';
import { IngestionTaxiiCollectionPopoverEditionQuery$data } from '@components/data/ingestionTaxiiCollection/__generated__/IngestionTaxiiCollectionPopoverEditionQuery.graphql';
import {
  IngestionTaxiiCollectionLinesPaginationQuery$variables,
} from '@components/data/ingestionTaxiiCollection/__generated__/IngestionTaxiiCollectionLinesPaginationQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { deleteNode } from '../../../../utils/store';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Transition from '../../../../components/Transition';
import IngestionTaxiiCollectionEdition, { ingestionTaxiiCollectionMutationFieldPatch } from './IngestionTaxiiCollectionEdition';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';

const ingestionTaxiiPopoverDeletionMutation = graphql`
  mutation IngestionTaxiiCollectionPopoverDeletionMutation($id: ID!) {
    ingestionTaxiiCollectionDelete(id: $id)
  }
`;

const ingestionTaxiiEditionQuery = graphql`
  query IngestionTaxiiCollectionPopoverEditionQuery($id: String!) {
    ingestionTaxiiCollection(id: $id) {
      id
      name
      description
      ingestion_running
      ...IngestionTaxiiCollectionEdition_ingestionTaxii
    }
  }
`;

interface IngestionTaxiiPopoverProps {
  ingestionTaxiiId: string;
  running?: boolean | null;
  paginationOptions?: IngestionTaxiiCollectionLinesPaginationQuery$variables | null | undefined;
}

const IngestionTaxiiPopover: FunctionComponent<IngestionTaxiiPopoverProps> = ({
  ingestionTaxiiId,
  running,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);
  const [displayUpdate, setDisplayUpdate] = useState(false);
  const [displayStart, setDisplayStart] = useState(false);
  const [starting, setStarting] = useState(false);
  const [displayStop, setDisplayStop] = useState(false);
  const [stopping, setStopping] = useState(false);

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
          'Pagination_ingestionTaxiiCollections',
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

  const [commitStart] = useApiMutation(ingestionTaxiiCollectionMutationFieldPatch);
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

  const [commitStop] = useApiMutation(ingestionTaxiiCollectionMutationFieldPatch);
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
      </Menu>
      <QueryRenderer
        query={ingestionTaxiiEditionQuery}
        variables={{ id: ingestionTaxiiId }}
        render={({ props }: { props: IngestionTaxiiCollectionPopoverEditionQuery$data }) => {
          if (props) {
            return (
              <IngestionTaxiiCollectionEdition
                ingestionTaxiiCollection={props.ingestionTaxiiCollection}
                handleClose={handleCloseUpdate}
                open={displayUpdate}
              />
            );
          }
          return <div />;
        }}
      />
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this TAXII ingester?')}
      />
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

import React, { FunctionComponent, useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql, useMutation } from 'react-relay';
import { useNavigate } from 'react-router-dom-v5-compat';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import DataComponentEditionContainer, { dataComponentEditionQuery } from './DataComponentEditionContainer';
import Transition from '../../../../components/Transition';
import { DataComponentEditionContainerQuery } from './__generated__/DataComponentEditionContainerQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

const DataComponentPopoverDeletionMutation = graphql`
  mutation DataComponentPopoverDeletionMutation($id: ID!) {
    dataComponentDelete(id: $id)
  }
`;

const DataComponentPopover: FunctionComponent<{ dataComponentId: string }> = ({
  dataComponentId,
}) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [displayDelete, setDisplayDelete] = useState<boolean>(false);
  const [displayEdit, setDisplayEdit] = useState<boolean>(false);
  const [deleting, setDeleting] = useState<boolean>(false);
  const handleOpen = (event: React.MouseEvent<HTMLElement>) => setAnchorEl(event.currentTarget);
  const handleClose = () => setAnchorEl(null);
  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };
  const handleCloseDelete = () => setDisplayDelete(false);
  const [commit] = useMutation(DataComponentPopoverDeletionMutation);
  const queryRef = useQueryLoading<DataComponentEditionContainerQuery>(
    dataComponentEditionQuery,
    { id: dataComponentId },
  );
  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id: dataComponentId,
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        navigate('/dashboard/techniques/data_components');
      },
    });
  };
  const handleOpenEdit = () => {
    setDisplayEdit(true);
    handleClose();
  };
  const handleCloseEdit = () => setDisplayEdit(false);
  return (
    <>
      <ToggleButton
        value="popover"
        size="small"
        style={{ marginRight: 3 }}
        onClick={handleOpen}
      >
        <MoreVert fontSize="small" color="primary" />
      </ToggleButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenEdit}>{t_i18n('Update')}</MenuItem>
        <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
          <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
        </Security>
      </Menu>
      <Dialog
        open={displayDelete}
        keepMounted={true}
        TransitionComponent={Transition}
        PaperProps={{ elevation: 1 }}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this data component?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDelete} disabled={deleting}>
            {t_i18n('Cancel')}
          </Button>
          <Button color="secondary" onClick={submitDelete} disabled={deleting}>
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
      {queryRef && (
        <React.Suspense fallback={<div />}>
          <DataComponentEditionContainer
            queryRef={queryRef}
            handleClose={handleCloseEdit}
            open={displayEdit}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default DataComponentPopover;

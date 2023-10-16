import React, { useState } from 'react';
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
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { RegionEditionContainerQuery } from './__generated__/RegionEditionContainerQuery.graphql';
import Transition from '../../../../components/Transition';
import RegionEditionContainer, { regionEditionQuery } from './RegionEditionContainer';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
}));

const RegionPopoverDeletionMutation = graphql`
  mutation RegionPopoverDeletionMutation($id: ID!) {
    regionEdit(id: $id) {
      delete
    }
  }
`;

const RegionPopover = ({ id }: { id: string }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<Element>();
  const [displayEdit, setDisplayEdit] = useState<boolean>(false);
  const [deleting, setDeleting] = useState<boolean>(false);
  const [displayDelete, setDisplayDelete] = useState<boolean>(false);

  const [commit] = useMutation(RegionPopoverDeletionMutation);
  const queryRef = useQueryLoading<RegionEditionContainerQuery>(
    regionEditionQuery,
    { id },
  );
  const handleOpen = (event: React.SyntheticEvent) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(undefined);
  };
  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };
  const handleCloseDelete = () => {
    setDisplayDelete(false);
  };
  const handleOpenEdit = () => {
    setDisplayEdit(true);
    handleClose();
  };
  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id,
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        navigate('/dashboard/locations/regions');
      },
    });
  };
  return (
    <div className={classes.container}>
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
        style={{ marginTop: 3 }}
        size="large"
      >
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenEdit}>{t('Update')}</MenuItem>
        <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
          <MenuItem onClick={handleOpenDelete}>{t('Delete')}</MenuItem>
        </Security>
      </Menu>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayDelete}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t('Do you want to delete this region?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDelete} disabled={deleting}>
            {t('Cancel')}
          </Button>
          <Button color="secondary" onClick={submitDelete} disabled={deleting}>
            {t('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <RegionEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
            open={displayEdit}
          />
        </React.Suspense>
      )}
    </div>
  );
};

export default RegionPopover;

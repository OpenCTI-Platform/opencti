import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Drawer from '@mui/material/Drawer';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql, useMutation } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { useNavigate } from 'react-router-dom-v5-compat';
import { PopoverProps } from '@mui/material/Popover';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import { Theme } from '../../../../components/Theme';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useDeletion from '../../../../utils/hooks/useDeletion';
import Transition from '../../../../components/Transition';
import ThreatActorIndividualEditionContainer, {
  ThreatActorIndividualEditionQuery,
} from './ThreatActorIndividualEditionContainer';
import {
  ThreatActorIndividualEditionContainerQuery,
} from './__generated__/ThreatActorIndividualEditionContainerQuery.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    margin: 0,
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
}));

const ThreatActorIndividualPopoverDeletionMutation = graphql`
  mutation ThreatActorIndividualPopoverDeletionMutation($id: ID!) {
    threatActorIndividualDelete(id: $id)
  }
`;

const ThreatActorIndividualPopover = ({
  id,
}: {
  id: string;
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);
  const [displayEdit, setDisplayEdit] = useState<boolean>(false);
  const [commit] = useMutation(ThreatActorIndividualPopoverDeletionMutation);
  const queryRef = useQueryLoading<ThreatActorIndividualEditionContainerQuery>(
    ThreatActorIndividualEditionQuery,
    { id },
  );
  const handleOpen = (event: React.SyntheticEvent) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(null);
  };
  const handleOpenEdit = () => {
    setDisplayEdit(true);
    handleClose();
  };
  const handleCloseEdit = () => {
    setDisplayEdit(false);
  };
  const {
    deleting,
    handleOpenDelete,
    displayDelete,
    handleCloseDelete,
    setDeleting,
  } = useDeletion({ handleClose });

  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id,
      },
      configs: [
        {
          type: 'NODE_DELETE',
          deletedIDFieldName: 'id',
        },
      ],
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        navigate('/dashboard/threat_actors/threat_actors_individuals');
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
        <Menu
          anchorEl={anchorEl}
          open={Boolean(anchorEl)}
          onClose={handleClose}
        >
          <MenuItem onClick={handleOpenEdit}>
            {t('Update')}
          </MenuItem>
          <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
            <MenuItem onClick={handleOpenDelete}>
              {t('Delete')}
            </MenuItem>
          </Security>
        </Menu>
        <Dialog
          open={displayDelete}
          PaperProps={{ elevation: 1 }}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={handleCloseDelete}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to delete this threat actor individual?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={handleCloseDelete}
              disabled={deleting}
            >
              {t('Cancel')}
            </Button>
            <Button
              color="secondary"
              onClick={submitDelete}
              disabled={deleting}
            >
              {t('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
        <Drawer
          open={displayEdit}
          anchor="right"
          elevation={1}
          sx={{ zIndex: 1202 }}
          classes={{ paper: classes.drawerPaper }}
          onClose={handleCloseEdit}
        >
          {queryRef && (
            <React.Suspense
              fallback={<Loader variant={LoaderVariant.inElement} />}
            >
              <ThreatActorIndividualEditionContainer
                queryRef={queryRef}
                handleClose={handleCloseEdit}
              />
            </React.Suspense>
          )}
        </Drawer>
      </div>
  );
};

export default ThreatActorIndividualPopover;

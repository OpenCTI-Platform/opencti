import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import Drawer from '@mui/material/Drawer';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import Slide, { SlideProps } from '@mui/material/Slide';
import { MoreVertOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useHistory } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ExternalReferenceEditionContainer from './ExternalReferenceEditionContainer';
import { Theme } from '../../../../components/Theme';
import {
  ExternalReferencePopoverEditionQuery$data,
} from './__generated__/ExternalReferencePopoverEditionQuery.graphql';
import { deleteNodeFromId } from '../../../../utils/store';

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

const Transition = React.forwardRef((props: SlideProps, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

export const externalReferencePopoverDeletionMutation = graphql`
  mutation ExternalReferencePopoverDeletionMutation($id: ID!) {
    externalReferenceEdit(id: $id) {
      delete
    }
  }
`;

const externalReferenceEditionQuery = graphql`
  query ExternalReferencePopoverEditionQuery($id: String!) {
    externalReference(id: $id) {
      ...ExternalReferenceEditionContainer_externalReference
    }
  }
`;

interface ExternalReferencePopoverProps {
  id: string,
  handleRemove: (() => void) | undefined,
  entityId: string,
  externalReferenceFileId?: string | null
}

const ExternalReferencePopover: FunctionComponent<ExternalReferencePopoverProps> = ({ id, handleRemove, entityId, externalReferenceFileId }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const history = useHistory();

  const [anchorEl, setAnchorEl] = useState<Element | null>(null);
  const [displayEdit, setDisplayEdit] = useState(false);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [displayWarning, setDisplayWarning] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const handleOpen = (event: React.SyntheticEvent) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleOpenUpdate = () => {
    setDisplayEdit(true);
    handleClose();
  };

  const handleCloseUpdate = () => {
    setDisplayEdit(false);
  };

  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };

  const handleCloseDelete = () => {
    setDisplayDelete(false);
  };

  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      mutation: externalReferencePopoverDeletionMutation,
      variables: {
        id,
      },
      updater: (store: RecordSourceSelectorProxy) => {
        deleteNodeFromId(store, entityId, 'Pagination_externalReferences', {}, id);
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        if (handleRemove) {
          handleCloseDelete();
        } else {
          history.push('/dashboard/analysis/external_references');
        }
      },
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
  };

  const submitDeleteRefAndFile = () => {
    submitDelete();
  };

  const handleOpenWarning = () => {
    setDisplayWarning(true);
    setDisplayDelete(false);
    handleClose();
  };

  const handleCloseWarning = () => {
    setDisplayWarning(false);
  };

  const submitDeleteAttempt = () => {
    if (externalReferenceFileId) {
      handleOpenWarning();
    } else {
      submitDelete();
    }
  };

  return (
    <span className={classes.container}>
        <IconButton
          onClick={handleOpen}
          aria-haspopup="true"
          style={{ marginTop: 3 }}
          size="large"
        >
          <MoreVertOutlined />
        </IconButton>
        <Menu
          anchorEl={anchorEl}
          open={Boolean(anchorEl)}
          onClose={handleClose}
        >
          <MenuItem onClick={handleOpenUpdate}>
            {t('Update')}
          </MenuItem>
          {handleRemove && (
            <MenuItem
              onClick={() => {
                handleRemove();
                handleClose();
              }}
            >
              {t('Remove from this object')}
            </MenuItem>
          )}
          <MenuItem onClick={handleOpenDelete}>
            {t('Delete')}
          </MenuItem>
        </Menu>
        <Drawer
          open={displayEdit}
          anchor="right"
          elevation={1}
          sx={{ zIndex: 1202 }}
          classes={{ paper: classes.drawerPaper }}
          onClose={handleCloseUpdate}
        >
          <QueryRenderer
            query={externalReferenceEditionQuery}
            variables={{ id }}
            render={({ props }: { props: ExternalReferencePopoverEditionQuery$data }) => {
              if (props && props.externalReference) {
                return (
                  <ExternalReferenceEditionContainer
                    externalReference={props.externalReference}
                    handleClose={handleCloseUpdate}
                  />
                );
              }
              return <Loader variant={LoaderVariant.inElement} />;
            }}
          />
        </Drawer>
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={displayDelete}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={handleCloseDelete}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to delete this external reference?')}
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
              onClick={submitDeleteAttempt}
              disabled={deleting}
            >
              {t('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayWarning}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseWarning}
      >
          <DialogContent>
            <DialogContentText>
              {t('This external reference is linked to a file. If you delete it, the file will be deleted as well. Do you still want to delete this external reference?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={handleCloseWarning}
              disabled={deleting}
            >
              {t('Cancel')}
            </Button>
            <Button
              color="secondary"
              onClick={submitDeleteRefAndFile}
              disabled={deleting}
            >
              {t('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
      </span>
  );
};

export default ExternalReferencePopover;

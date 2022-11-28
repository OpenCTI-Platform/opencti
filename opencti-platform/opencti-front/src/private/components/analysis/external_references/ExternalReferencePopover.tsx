import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { Store } from 'relay-runtime';
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
import { deleteNode } from '../../../../utils/store';

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

const externalReferencePopoverDeletionMutation = graphql`
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
  paginationOptions?: { search: string, orderMode: string, orderBy: string },
}

const ExternalReferencePopover: FunctionComponent<ExternalReferencePopoverProps> = ({ id, handleRemove, entityId, paginationOptions }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const history = useHistory();

  const [anchorEl, setAnchorEl] = useState<Element | null>(null);
  const [displayEdit, setDisplayEdit] = useState(false);
  const [displayDelete, setDisplayDelete] = useState(false);
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
      updater: (store: Store) => {
        deleteNode(store, 'Pagination_externalReferences', paginationOptions, entityId);
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
              onClick={submitDelete}
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

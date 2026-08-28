import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import MoreVert from '@mui/icons-material/MoreVert';
import DialogActions from '@mui/material/DialogActions';
import DialogContentText from '@mui/material/DialogContentText';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Slide from '@mui/material/Slide';
import withStyles from '@mui/styles/withStyles';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import React, { useState } from 'react';
import { graphql } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import Drawer from '../../common/drawer/Drawer';
import TaxiiCollectionEdition from './TaxiiCollectionEdition';

const styles = (theme) => ({
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
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const taxiiCollectionPopoverDeletionMutation = graphql`
  mutation TaxiiPopoverDeletionMutation($id: ID!) {
    taxiiCollectionEdit(id: $id) {
      delete
    }
  }
`;

const taxiiCollectionEditionQuery = graphql`
  query TaxiiPopoverEditionQuery($id: String!) {
    taxiiCollection(id: $id) {
      id
      name
      description
      filters
      ...TaxiiCollectionEdition_taxiiCollection
    }
  }
`;

const TaxiiCollectionPopover = (props) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayUpdate, setDisplayUpdate] = useState(false);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const handleOpen = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
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

  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      mutation: taxiiCollectionPopoverDeletionMutation,
      variables: {
        id: props.taxiiCollectionId,
      },
      updater: (store) => {
        const container = store.getRoot();
        const payload = store.getRootField('taxiiCollectionEdit');
        const userProxy = store.get(container.getDataID());
        const conn = ConnectionHandler.getConnection(
          userProxy,
          'Pagination_taxiiCollections',
          props.paginationOptions,
        );
        ConnectionHandler.deleteNode(conn, payload.getValue('delete'));
      },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
      },
    });
  };

  const { classes, taxiiCollectionId } = props;
  return (
    <div className={classes.container}>
      <IconButton
        aria-label={t_i18n('Open menu')}
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
        <MenuItem onClick={handleOpenUpdate}>
          {t_i18n('Update')}
        </MenuItem>
        <MenuItem onClick={handleOpenDelete}>
          {t_i18n('Delete')}
        </MenuItem>
      </Menu>
      <Drawer
        open={displayUpdate}
        onClose={handleCloseUpdate}
        title={t_i18n('Update a TAXII collection')}
      >
        <QueryRenderer
          query={taxiiCollectionEditionQuery}
          variables={{ id: taxiiCollectionId }}
          render={({ props }) => {
            if (props) {
              return (
                <TaxiiCollectionEdition
                  taxiiCollection={props.taxiiCollection}
                />
              );
            }
            return <div />;
          }}
        />
      </Drawer>
      <Dialog
        open={displayDelete}
        onClose={handleCloseDelete}
        title={t_i18n('Are you sure?')}
        size="small"
      >
        <DialogContentText>
          {t_i18n('Do you want to delete this collection?')}
        </DialogContentText>
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
            {t_i18n('Confirm')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

TaxiiCollectionPopover.propTypes = {
  taxiiCollectionId: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
};

export default compose(withStyles(styles))(TaxiiCollectionPopover);

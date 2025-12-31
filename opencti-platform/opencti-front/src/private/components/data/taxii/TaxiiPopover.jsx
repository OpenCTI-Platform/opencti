import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import Slide from '@mui/material/Slide';
import MoreVert from '@mui/icons-material/MoreVert';
import { ConnectionHandler } from 'relay-runtime';
import DialogTitle from '@mui/material/DialogTitle';
import Drawer from '../../common/drawer/Drawer';
import inject18n from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
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

class TaxiiCollectionPopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      displayUpdate: false,
      displayDelete: false,
      deleting: false,
    };
  }

  handleOpen(event) {
    this.setState({ anchorEl: event.currentTarget });
  }

  handleClose() {
    this.setState({ anchorEl: null });
  }

  handleOpenUpdate() {
    this.setState({ displayUpdate: true });
    this.handleClose();
  }

  handleCloseUpdate() {
    this.setState({ displayUpdate: false });
  }

  handleOpenDelete() {
    this.setState({ displayDelete: true });
    this.handleClose();
  }

  handleCloseDelete() {
    this.setState({ displayDelete: false });
  }

  submitDelete() {
    this.setState({ deleting: true });
    commitMutation({
      mutation: taxiiCollectionPopoverDeletionMutation,
      variables: {
        id: this.props.taxiiCollectionId,
      },
      updater: (store) => {
        const container = store.getRoot();
        const payload = store.getRootField('taxiiCollectionEdit');
        const userProxy = store.get(container.getDataID());
        const conn = ConnectionHandler.getConnection(
          userProxy,
          'Pagination_taxiiCollections',
          this.props.paginationOptions,
        );
        ConnectionHandler.deleteNode(conn, payload.getValue('delete'));
      },
      onCompleted: () => {
        this.setState({ deleting: false });
        this.handleCloseDelete();
      },
    });
  }

  render() {
    const { classes, t, taxiiCollectionId } = this.props;
    return (
      <div className={classes.container}>
        <IconButton
          onClick={this.handleOpen.bind(this)}
          aria-haspopup="true"
          style={{ marginTop: 3 }}
          color="primary"
        >
          <MoreVert />
        </IconButton>
        <Menu
          anchorEl={this.state.anchorEl}
          open={Boolean(this.state.anchorEl)}
          onClose={this.handleClose.bind(this)}
        >
          <MenuItem onClick={this.handleOpenUpdate.bind(this)}>
            {t('Update')}
          </MenuItem>
          <MenuItem onClick={this.handleOpenDelete.bind(this)}>
            {t('Delete')}
          </MenuItem>
        </Menu>
        <Drawer
          open={this.state.displayUpdate}
          onClose={this.handleCloseUpdate.bind(this)}
          title={t('Update a TAXII collection')}
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
          slotProps={{ paper: { elevation: 1 } }}
          open={this.state.displayDelete}
          keepMounted={true}
          slots={{ transition: Transition }}
          onClose={this.handleCloseDelete.bind(this)}
        >
          <DialogTitle>
            {t('Are you sure?')}
          </DialogTitle>
          <DialogContent>
            <DialogContentText>
              {t('Do you want to delete this collection?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              variant="secondary"
              onClick={this.handleCloseDelete.bind(this)}
              disabled={this.state.deleting}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.submitDelete.bind(this)}
              disabled={this.state.deleting}
            >
              {t('Confirm')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

TaxiiCollectionPopover.propTypes = {
  taxiiCollectionId: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(TaxiiCollectionPopover);

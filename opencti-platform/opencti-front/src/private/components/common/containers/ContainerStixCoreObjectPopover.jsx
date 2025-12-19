import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import MoreVert from '@mui/icons-material/MoreVert';
import { ConnectionHandler } from 'relay-runtime';
import Alert from '@mui/material/Alert';
import { Form, Formik } from 'formik';
import DialogTitle from '@mui/material/DialogTitle';
import CommitMessage from '../form/CommitMessage';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import { deleteElementByValue } from '../../../../utils/utils';
import Transition from '../../../../components/Transition';
import { serializeObjectB64 } from '../../../../utils/object';

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

export const containerStixCoreObjectPopoverRemoveMutation = graphql`
  mutation ContainerStixCoreObjectPopoverRemoveMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
    $commitMessage: String
    $references: [String]
  ) {
    containerEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type, commitMessage: $commitMessage, references: $references) {
        id
      }
    }
  }
`;

export const containerStixCoreObjectPopoverFieldPatchMutation = graphql`
  mutation ContainerStixCoreObjectPopoverFieldPatchMutation(
    $id: ID!
    $input: [EditInput!]!
    $commitMessage: String
    $references: [String]
  ) {
    stixDomainObjectEdit(id: $id) {
      fieldPatch(input: $input, commitMessage: $commitMessage, references: $references) {
        ... on Report {
          content_mapping
        }
        ... on Case {
          content_mapping
        }
        ... on Grouping {
          content_mapping
        }
      }
    }
  }
`;

export const containerStixCoreObjectPopoverDeleteMutation = graphql`
  mutation ContainerStixCoreObjectPopoverDeleteMutation($id: ID!) {
    stixCoreObjectEdit(id: $id) {
      delete
    }
  }
`;

class ContainerStixCoreObjectPopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      displayDeleteMapping: false,
      displayRemove: false,
      displayDelete: false,
      removing: false,
      deleting: false,
      deletingMapping: false,
      referenceDialogOpened: false,
    };
  }

  handleOpen(event) {
    this.setState({ anchorEl: event.currentTarget });
    event.stopPropagation();
  }

  handleClose() {
    this.setState({ anchorEl: null });
  }

  handleOpenRemove() {
    this.setState({ displayRemove: true });
    this.handleClose();
  }

  handleCloseRemove() {
    this.setState({ removing: false, displayRemove: false });
  }

  handleSubmitRemove() {
    const { enableReferences } = this.props;
    if (enableReferences) {
      this.setState({ referenceDialogOpened: true });
    } else {
      this.submitRemove();
    }
  }

  handleOpenDeleteMapping() {
    this.setState({ displayDeleteMapping: true });
    this.handleClose();
  }

  handleCloseDeleteMapping() {
    this.setState({ deletingMapping: false, displayDeleteMapping: false });
  }

  handleSubmitDeleteMapping() {
    const { enableReferences } = this.props;
    if (enableReferences) {
      this.setState({ referenceDialogOpened: true });
    } else {
      this.submitDeleteMapping();
    }
  }

  handleOpenDelete() {
    this.setState({ displayDelete: true });
    this.handleClose();
  }

  handleCloseDelete() {
    this.setState({ deleting: false, displayDelete: false });
  }

  submitDeleteMapping(commitMessage = '', references = [], setSubmitting = null, resetForm = null) {
    const { containerId, toStandardId, contentMappingData } = this.props;
    this.setState({ deletingMapping: true });
    const newMappingData = deleteElementByValue(contentMappingData, toStandardId);
    commitMutation({
      mutation: containerStixCoreObjectPopoverFieldPatchMutation,
      variables: {
        id: containerId,
        input: {
          key: 'content_mapping',
          value: serializeObjectB64(newMappingData),
        },
        commitMessage,
        references,
      },
      onCompleted: () => {
        this.handleCloseDeleteMapping();
        if (setSubmitting) setSubmitting(false);
        if (resetForm) resetForm(true);
      },
    });
  }

  submitRemove(commitMessage = '', references = [], setSubmitting = null, resetForm = null) {
    const {
      containerId,
      toId,
      relationshipType,
      paginationKey,
      paginationOptions,
      selectedElements,
      setSelectedElements,
    } = this.props;
    this.setState({ removing: true });
    commitMutation({
      mutation: containerStixCoreObjectPopoverRemoveMutation,
      variables: {
        id: containerId,
        toId,
        relationship_type: relationshipType,
        commitMessage,
        references,
      },
      updater: (store) => {
        // ID is not valid pagination options, will be handled better when hooked
        const options = { ...paginationOptions };
        delete options.id;
        delete options.count;
        if (toId) {
          const conn = ConnectionHandler.getConnection(
            store.get(containerId),
            paginationKey,
            options,
          );
          ConnectionHandler.deleteNode(conn, toId);
        }
      },
      onCompleted: () => {
        this.submitDeleteMapping(commitMessage, references, setSubmitting, resetForm);
        this.handleCloseRemove();
        const newSelectedElements = R.omit([toId], selectedElements);
        setSelectedElements?.(newSelectedElements);
      },
      setSubmitting,
    });
  }

  submitDelete() {
    const {
      containerId,
      toId,
      paginationKey,
      paginationOptions,
      selectedElements,
      setSelectedElements,
    } = this.props;
    this.setState({ deleting: true });
    commitMutation({
      mutation: containerStixCoreObjectPopoverDeleteMutation,
      variables: {
        id: toId,
      },
      updater: (store) => {
        // ID is not valid pagination options, will be handled better when hooked
        const options = { ...paginationOptions };
        delete options.id;
        delete options.count;
        if (toId) {
          const conn = ConnectionHandler.getConnection(
            store.get(containerId),
            paginationKey,
            options,
          );
          ConnectionHandler.deleteNode(conn, toId);
        }
      },
      onCompleted: () => {
        this.handleCloseDelete();
        const newSelectedElements = R.omit([toId], selectedElements);
        setSelectedElements?.(newSelectedElements);
      },
    });
  }

  closeReferencesPopup() {
    this.setState({ referenceDialogOpened: false });
  }

  submitReference(values, { setSubmitting, resetForm }) {
    const { displayRemove, displayDeleteMapping } = this.state;
    const references = (values.references || []).map((ref) => ref.value);
    if (displayRemove) this.submitRemove(values.message, references, setSubmitting, resetForm);
    else if (displayDeleteMapping) this.submitDeleteMapping(values.message, references, setSubmitting, resetForm);
  }

  render() {
    const { classes, t, theme, contentMappingData, mapping, containerId, enableReferences } = this.props;
    const { referenceDialogOpened } = this.state;
    return (
      <div className={classes.container}>
        <IconButton
          color="primary"
          onClick={this.handleOpen.bind(this)}
          disabled={this.props.menuDisable ?? false}
          aria-haspopup="true"
        >
          <MoreVert />
        </IconButton>
        <Menu
          anchorEl={this.state.anchorEl}
          open={Boolean(this.state.anchorEl)}
          onClose={this.handleClose.bind(this)}
        >
          {contentMappingData && mapping && mapping > 0 && (
            <MenuItem onClick={this.handleOpenDeleteMapping.bind(this)}>
              {t('Delete mapping')}
            </MenuItem>
          )}
          <MenuItem onClick={this.handleOpenRemove.bind(this)}>
            {t('Remove')}
          </MenuItem>
          <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
            <MenuItem
              onClick={this.handleOpenDelete.bind(this)}
              style={{ color: theme.palette.warning.main }}
            >
              {t('Delete')}
            </MenuItem>
          </Security>
        </Menu>
        <Dialog
          slotProps={{ paper: { elevation: 1 } }}
          open={this.state.displayDeleteMapping}
          keepMounted={true}
          slots={{ transition: Transition }}
          onClose={this.handleCloseDeleteMapping.bind(this)}
        >
          <DialogTitle>
            {t('Are you sure?')}
          </DialogTitle>
          <DialogContent>
            <DialogContentText>
              {t('Do you want to delete the mapping for this entity?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              variant="secondary"
              onClick={this.handleCloseDeleteMapping.bind(this)}
              disabled={this.state.deletingMapping}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.handleSubmitDeleteMapping.bind(this)}
              disabled={this.state.deletingMapping}
            >
              {t('Confirm')}
            </Button>
          </DialogActions>
        </Dialog>
        <Dialog
          slotProps={{ paper: { elevation: 1 } }}
          open={this.state.displayRemove}
          keepMounted={true}
          slots={{ transition: Transition }}
          onClose={this.handleCloseRemove.bind(this)}
        >
          <DialogTitle>
            {t('Are you sure?')}
          </DialogTitle>
          <DialogContent>
            <DialogContentText>
              {t('Do you want to remove the entity from this container?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              variant="secondary"
              onClick={this.handleCloseRemove.bind(this)}
              disabled={this.state.removing}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.handleSubmitRemove.bind(this)}
              disabled={this.state.removing}
            >
              {t('Confirm')}
            </Button>
          </DialogActions>
        </Dialog>
        {enableReferences && (
          <Formik
            initialValues={{ message: '', references: [] }}
            onSubmit={this.submitReference.bind(this)}
          >
            {({
              submitForm,
              isSubmitting,
              setFieldValue,
              values,
            }) => (
              <Form>
                <CommitMessage
                  handleClose={this.closeReferencesPopup.bind(this)}
                  open={referenceDialogOpened}
                  submitForm={submitForm}
                  disabled={isSubmitting}
                  setFieldValue={setFieldValue}
                  values={values.references}
                  id={containerId}
                  noStoreUpdate={true}
                />
              </Form>
            )}
          </Formik>
        )}
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
              {t('Do you want to delete this entity?')}
              <Alert severity="warning" variant="outlined" style={{ marginTop: 20 }}>
                {t(
                  'You are about to completely delete the entity from the platform (not only from the container), be sure of what you are doing.',
                )}
              </Alert>
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

ContainerStixCoreObjectPopover.propTypes = {
  containerId: PropTypes.string,
  toId: PropTypes.string,
  toStandardId: PropTypes.string,
  relationshipType: PropTypes.string,
  paginationKey: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  selectedElements: PropTypes.object,
  setSelectedElements: PropTypes.func,
  contentMappingData: PropTypes.object,
  mapping: PropTypes.number,
  enableReferences: PropTypes.bool,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(ContainerStixCoreObjectPopover);

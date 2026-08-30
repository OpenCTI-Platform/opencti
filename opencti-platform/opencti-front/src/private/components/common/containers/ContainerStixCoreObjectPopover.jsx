import { useState } from 'react';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import MoreVert from '@mui/icons-material/MoreVert';
import Alert from '@mui/material/Alert';
import DialogActions from '@mui/material/DialogActions';
import DialogContentText from '@mui/material/DialogContentText';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import { Form, Formik } from 'formik';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import { serializeObjectB64 } from '../../../../utils/object';
import Security from '../../../../utils/Security';
import { deleteElementByValue } from '../../../../utils/utils';
import CommitMessage from '../form/CommitMessage';
import stopEvent from '../../../../utils/domEvent';

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

const ContainerStixCoreObjectPopover = (props) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayDeleteMapping, setDisplayDeleteMapping] = useState(false);
  const [displayRemove, setDisplayRemove] = useState(false);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deletingMapping, setDeletingMapping] = useState(false);
  const [referenceDialogOpened, setReferenceDialogOpened] = useState(false);
  const handleOpen = (event) => {
    stopEvent(event);
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleOpenRemove = () => {
    setDisplayRemove(true);
    handleClose();
  };

  const handleCloseRemove = () => {
    setRemoving(false);
    setDisplayRemove(false);
  };

  const handleSubmitRemove = () => {
    const { enableReferences } = props;
    if (enableReferences) {
      setReferenceDialogOpened(true);
    } else {
      submitRemove();
    }
  };

  const handleOpenDeleteMapping = () => {
    setDisplayDeleteMapping(true);
    handleClose();
  };

  const handleCloseDeleteMapping = () => {
    setDeletingMapping(false);
    setDisplayDeleteMapping(false);
  };

  const handleSubmitDeleteMapping = () => {
    const { enableReferences } = props;
    if (enableReferences) {
      setReferenceDialogOpened(true);
    } else {
      submitDeleteMapping();
    }
  };

  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };

  const handleCloseDelete = () => {
    setDeleting(false);
    setDisplayDelete(false);
  };

  const submitDeleteMapping = (commitMessage = '', references = [], setSubmitting = null, resetForm = null) => {
    const { containerId, toStandardId, contentMappingData } = props;
    setDeletingMapping(true);
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
        handleCloseDeleteMapping();
        if (setSubmitting) setSubmitting(false);
        if (resetForm) resetForm(true);
      },
    });
  };

  const submitRemove = (commitMessage = '', references = [], setSubmitting = null, resetForm = null) => {
    const {
      containerId,
      toId,
      relationshipType,
      paginationKey,
      paginationOptions,
      selectedElements,
      setSelectedElements,
    } = props;
    setRemoving(true);
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
        submitDeleteMapping(commitMessage, references, setSubmitting, resetForm);
        handleCloseRemove();
        const newSelectedElements = R.omit([toId], selectedElements);
        setSelectedElements?.(newSelectedElements);
      },
      setSubmitting,
    });
  };

  const submitDelete = () => {
    const {
      containerId,
      toId,
      paginationKey,
      paginationOptions,
      selectedElements,
      setSelectedElements,
    } = props;
    setDeleting(true);
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
        handleCloseDelete();
        const newSelectedElements = R.omit([toId], selectedElements);
        setSelectedElements?.(newSelectedElements);
      },
    });
  };

  const closeReferencesPopup = () => {
    setReferenceDialogOpened(false);
  };

  const submitReference = (values, { setSubmitting, resetForm }) => {
    const references = (values.references || []).map((ref) => ref.value);
    if (displayRemove) submitRemove(values.message, references, setSubmitting, resetForm);
    else if (displayDeleteMapping) submitDeleteMapping(values.message, references, setSubmitting, resetForm);
  };

  const { classes, theme, contentMappingData, mapping, containerId, enableReferences } = props;
  return (
    <div className={classes.container}>
      <IconButton
        aria-label={t_i18n('Open menu')}
        color="primary"
        onClick={handleOpen}
        disabled={props.menuDisable ?? false}
        aria-haspopup="true"
      >
        <MoreVert />
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
      >
        {contentMappingData && mapping && mapping > 0 && (
          <MenuItem onClick={handleOpenDeleteMapping}>
            {t_i18n('Delete mapping')}
          </MenuItem>
        )}
        <MenuItem onClick={handleOpenRemove}>
          {t_i18n('Remove')}
        </MenuItem>
        <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
          <MenuItem
            onClick={handleOpenDelete}
            style={{ color: theme.palette.warning.main }}
          >
            {t_i18n('Delete')}
          </MenuItem>
        </Security>
      </Menu>
      <Dialog
        open={displayDeleteMapping}
        onClose={handleCloseDeleteMapping}
        title={t_i18n('Are you sure?')}
        size="small"
      >
        <DialogContentText>
          {t_i18n('Do you want to delete the mapping for this entity?')}
        </DialogContentText>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={handleCloseDeleteMapping}
            disabled={deletingMapping}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={handleSubmitDeleteMapping}
            disabled={deletingMapping}
          >
            {t_i18n('Confirm')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={displayRemove}
        onClose={handleCloseRemove}
        title={t_i18n('Are you sure?')}
        size="small"
      >
        <DialogContentText>
          {t_i18n('Do you want to remove the entity from this container?')}
        </DialogContentText>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={handleCloseRemove}
            disabled={removing}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={handleSubmitRemove}
            disabled={removing}
          >
            {t_i18n('Confirm')}
          </Button>
        </DialogActions>
      </Dialog>
      {enableReferences && (
        <Formik
          initialValues={{ message: '', references: [] }}
          onSubmit={submitReference}
        >
          {({
            submitForm,
            isSubmitting,
            setFieldValue,
            values,
          }) => (
            <Form>
              <CommitMessage
                handleClose={closeReferencesPopup}
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
        open={displayDelete}
        onClose={handleCloseDelete}
        title={t_i18n('Are you sure?')}
        size="small"
      >
        <DialogContentText>
          {t_i18n('Do you want to delete this entity?')}
          <Alert severity="warning" variant="outlined" style={{ marginTop: 20 }}>
            {t_i18n(
              'You are about to completely delete the entity from the platform (not only from the container), be sure of what you are doing.',
            )}
          </Alert>
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

ContainerStixCoreObjectPopover.propTypes = {
  containerId: PropTypes.string,
  toId: PropTypes.string,
  toStandardId: PropTypes.string,
  relationshipType: PropTypes.string,
  paginationKey: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  selectedElements: PropTypes.object,
  setSelectedElements: PropTypes.func,
  contentMappingData: PropTypes.object,
  mapping: PropTypes.number,
  enableReferences: PropTypes.bool,
};

export default compose(
  withTheme,
  withStyles(styles),
)(ContainerStixCoreObjectPopover);

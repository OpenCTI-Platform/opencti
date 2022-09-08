import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createPaginationContainer } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Button from '@mui/material/Button';
import Avatar from '@mui/material/Avatar';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import { ExpandMoreOutlined, ExpandLessOutlined } from '@mui/icons-material';
import Slide from '@mui/material/Slide';
import { interval } from 'rxjs';
import { Field, Form, Formik } from 'formik';
import DialogTitle from '@mui/material/DialogTitle';
import { includes } from 'ramda';
import MenuItem from '@mui/material/MenuItem';
import * as Yup from 'yup';
import inject18n from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import AddExternalReferences from './AddExternalReferences';
import { externalReferenceMutationRelationDelete } from './AddExternalReferencesLines';
import Security, {
  KNOWLEDGE_KNENRICHMENT,
  KNOWLEDGE_KNUPDATE,
  KNOWLEDGE_KNUPLOAD,
} from '../../../../utils/Security';
import ExternalReferenceEnrichment from './ExternalReferenceEnrichment';
import FileLine from '../../common/files/FileLine';
import { FIVE_SECONDS } from '../../../../utils/Time';
import FileUploader from '../../common/files/FileUploader';
import ExternalReferencePopover from './ExternalReferencePopover';
import SelectField from '../../../../components/SelectField';
import {
  scopesConn,
  stixCoreObjectFilesAndHistoryAskJobImportMutation,
} from '../../common/stix_core_objects/StixCoreObjectFilesAndHistory';

const interval$ = interval(FIVE_SECONDS);

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '-4px 0 0 0',
    padding: 0,
    borderRadius: 6,
    position: 'relative',
  },
  avatar: {
    width: 24,
    height: 24,
    backgroundColor: theme.palette.primary.main,
  },
  avatarDisabled: {
    width: 24,
    height: 24,
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
  buttonExpand: {
    position: 'absolute',
    left: 0,
    bottom: 0,
    width: '100%',
    height: 25,
    color: theme.palette.primary.main,
    backgroundColor:
      theme.palette.mode === 'dark'
        ? 'rgba(255, 255, 255, .1)'
        : 'rgba(0, 0, 0, .1)',
    borderTopLeftRadius: 0,
    borderTopRightRadius: 0,
    '&:hover': {
      backgroundColor:
        theme.palette.mode === 'dark'
          ? 'rgba(255, 255, 255, .2)'
          : 'rgba(0, 0, 0, .2)',
    },
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const importValidation = (t) => Yup.object().shape({
  connector_id: Yup.string().required(t('This field is required')),
});

class StixCoreObjectExternalReferencesLinesContainer extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayDialog: false,
      displayExternalLink: false,
      externalLink: null,
      removeExternalReference: null,
      removing: false,
      expanded: false,
      fileToImport: null,
    };
  }

  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetchConnection(200);
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  handleToggleExpand() {
    this.setState({ expanded: !this.state.expanded });
  }

  handleOpenDialog(externalReferenceEdge) {
    const openedState = {
      displayDialog: true,
      removeExternalReference: externalReferenceEdge,
    };
    this.setState(openedState);
  }

  handleCloseDialog() {
    const closedState = {
      displayDialog: false,
      removeExternalReference: null,
    };
    this.setState(closedState);
  }

  handleRemoval() {
    this.setState({ removing: true });
    this.removeExternalReference(this.state.removeExternalReference);
  }

  handleOpenExternalLink(url) {
    this.setState({ displayExternalLink: true, externalLink: url });
  }

  handleCloseExternalLink() {
    this.setState({ displayExternalLink: false, externalLink: null });
  }

  handleBrowseExternalLink() {
    window.open(this.state.externalLink, '_blank');
    this.setState({ displayExternalLink: false, externalLink: null });
  }

  removeExternalReference(externalReferenceEdge) {
    commitMutation({
      mutation: externalReferenceMutationRelationDelete,
      variables: {
        id: externalReferenceEdge.node.id,
        fromId: this.props.stixCoreObjectId,
        relationship_type: 'external-reference',
      },
      updater: (store) => {
        const entity = store.get(this.props.stixCoreObjectId);
        const conn = ConnectionHandler.getConnection(
          entity,
          'Pagination_externalReferences',
        );
        ConnectionHandler.deleteNode(conn, externalReferenceEdge.node.id);
      },
      onCompleted: () => {
        this.setState({ removing: false });
        this.handleCloseDialog();
      },
    });
  }

  handleOpenImport(file) {
    this.setState({ fileToImport: file });
  }

  handleCloseImport() {
    this.setState({ fileToImport: null });
  }

  onSubmitImport(values, { setSubmitting, resetForm }) {
    const { stixCoreObjectId } = this.props;
    const { fileToImport } = this.state;
    commitMutation({
      mutation: stixCoreObjectFilesAndHistoryAskJobImportMutation,
      variables: {
        fileName: fileToImport.id,
        connectorId: values.connector_id,
        bypassEntityId: stixCoreObjectId,
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.handleCloseImport();
        MESSAGING$.notifySuccess('Import successfully asked');
      },
    });
  }

  render() {
    const { t, classes, stixCoreObjectId, data } = this.props;
    const { expanded, fileToImport } = this.state;
    const externalReferencesEdges = data.stixCoreObject
      ? data.stixCoreObject.externalReferences.edges : [];
    const expandable = externalReferencesEdges.length > 7;
    const importConnsPerFormat = data.connectorsForImport
      ? scopesConn(data.connectorsForImport) : {};
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('External references')}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPDATE]} placeholder={<div style={{ height: 29 }} />}>
          <AddExternalReferences
            stixCoreObjectOrStixCoreRelationshipId={stixCoreObjectId}
            stixCoreObjectOrStixCoreRelationshipReferences={
              data.stixCoreObject ? data.stixCoreObject.externalReferences.edges : []
            }
          />
        </Security>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} variant="outlined">
          {externalReferencesEdges.length > 0 ? (
            <List style={{ marginBottom: 0 }}>
              {R.take(expanded ? 200 : 7, externalReferencesEdges).map(
                (externalReferenceEdge) => {
                  const externalReference = externalReferenceEdge.node;
                  const externalReferenceId = externalReference.external_id
                    ? `(${externalReference.external_id})`
                    : '';
                  let externalReferenceSecondary = '';
                  if (
                    externalReference.url
                    && externalReference.url.length > 0
                  ) {
                    externalReferenceSecondary = externalReference.url;
                  } else if (
                    externalReference.description
                    && externalReference.description.length > 0
                  ) {
                    externalReferenceSecondary = externalReference.description;
                  }
                  if (externalReference.url) {
                    return (
                      <div key={externalReference.id}>
                        <ListItem
                          dense={true}
                          divider={true}
                          button={true}
                          onClick={this.handleOpenExternalLink.bind(
                            this,
                            externalReference.url,
                          )}
                        >
                          <ListItemIcon>
                            <Avatar classes={{ root: classes.avatar }}>
                              {externalReference.source_name.substring(0, 1)}
                            </Avatar>
                          </ListItemIcon>
                          <ListItemText
                            primary={`${externalReference.source_name} ${externalReferenceId}`}
                            secondary={truncate(externalReferenceSecondary, 90)}
                          />
                          <ListItemSecondaryAction>
                            <Security needs={[KNOWLEDGE_KNUPLOAD]}>
                              <FileUploader
                                entityId={externalReference.id}
                                onUploadSuccess={() => this.props.relay.refetchConnection(200)
                                }
                                color="inherit"
                              />
                            </Security>
                            <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
                              <ExternalReferenceEnrichment
                                externalReferenceId={externalReference.id}
                              />
                            </Security>
                            <Security needs={[KNOWLEDGE_KNUPDATE]}>
                              <ExternalReferencePopover
                                id={externalReference.id}
                                entityId={stixCoreObjectId}
                                handleRemove={this.handleOpenDialog.bind(
                                  this,
                                  externalReferenceEdge,
                                )}
                              />
                            </Security>
                          </ListItemSecondaryAction>
                        </ListItem>
                        {externalReference.importFiles.edges.length > 0 && (
                          <List>
                            {externalReference.importFiles.edges.map((file) => (
                              <FileLine
                                key={file.node.id}
                                dense={true}
                                file={file.node}
                                nested={true}
                                workNested={true}
                                connectors={
                                  importConnsPerFormat[
                                    file.node.metaData.mimetype
                                  ]
                                }
                                handleOpenImport={this.handleOpenImport.bind(
                                  this,
                                )}
                              />
                            ))}
                          </List>
                        )}
                      </div>
                    );
                  }
                  return (
                    <div key={externalReference.id}>
                      <ListItem dense={true} divider={true} button={false}>
                        <ListItemIcon>
                          <Avatar classes={{ root: classes.avatar }}>
                            {externalReference.source_name.substring(0, 1)}
                          </Avatar>
                        </ListItemIcon>
                        <ListItemText
                          primary={`${externalReference.source_name} ${externalReferenceId}`}
                          secondary={truncate(
                            externalReference.description,
                            120,
                          )}
                        />
                        <ListItemSecondaryAction>
                          <Security needs={[KNOWLEDGE_KNUPLOAD]}>
                            <FileUploader
                              entityId={externalReference.id}
                              onUploadSuccess={() => this.props.relay.refetchConnection(200)
                              }
                              color="inherit"
                            />
                          </Security>
                          <Security needs={[KNOWLEDGE_KNUPDATE]}>
                            <ExternalReferencePopover
                              id={externalReference.id}
                              entityId={stixCoreObjectId}
                              handleRemove={this.handleOpenDialog.bind(
                                this,
                                externalReferenceEdge,
                              )}
                            />
                          </Security>
                        </ListItemSecondaryAction>
                      </ListItem>
                      {externalReference.importFiles.edges.length > 0 && (
                        <List>
                          {externalReference.importFiles.edges.map((file) => (
                            <FileLine
                              key={file.node.id}
                              dense={true}
                              disableImport={true}
                              file={file.node}
                              nested={true}
                            />
                          ))}
                        </List>
                      )}
                    </div>
                  );
                },
              )}
            </List>
          ) : (
            <div
              style={{
                display: 'table',
                height: '100%',
                width: '100%',
                paddingTop: 15,
                paddingBottom: 15,
              }}
            >
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                {t('No entities of this type has been found.')}
              </span>
            </div>
          )}
          {expandable && (
            <Button
              variant="contained"
              size="small"
              onClick={this.handleToggleExpand.bind(this)}
              classes={{ root: classes.buttonExpand }}
            >
              {expanded ? (
                <ExpandLessOutlined fontSize="small" />
              ) : (
                <ExpandMoreOutlined fontSize="small" />
              )}
            </Button>
          )}
        </Paper>
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={this.state.displayDialog}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseDialog.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to remove this external reference?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseDialog.bind(this)}
              disabled={this.state.removing}
            >
              {t('Cancel')}
            </Button>
            <Button
              color="secondary"
              onClick={this.handleRemoval.bind(this)}
              disabled={this.state.removing}
            >
              {t('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={this.state.displayExternalLink}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseExternalLink.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to browse this external link?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button onClick={this.handleCloseExternalLink.bind(this)}>
              {t('Cancel')}
            </Button>
            <Button
              button={true}
              color="secondary"
              onClick={this.handleBrowseExternalLink.bind(this)}
            >
              {t('Browse the link')}
            </Button>
          </DialogActions>
        </Dialog>
        <Formik
          enableReinitialize={true}
          initialValues={{ connector_id: '' }}
          validationSchema={importValidation(t)}
          onSubmit={this.onSubmitImport.bind(this)}
          onReset={this.handleCloseImport.bind(this)}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form style={{ margin: '0 0 20px 0' }}>
              <Dialog
                PaperProps={{ elevation: 1 }}
                open={fileToImport}
                keepMounted={true}
                onClose={this.handleCloseImport.bind(this)}
                fullWidth={true}
              >
                <DialogTitle>{t('Launch an import')}</DialogTitle>
                <DialogContent>
                  <Field
                    component={SelectField}
                    variant="standard"
                    name="connector_id"
                    label={t('Connector')}
                    fullWidth={true}
                    containerstyle={{ width: '100%' }}
                  >
                    {data.connectorsForImport.map((connector, i) => {
                      const disabled = !fileToImport
                        || (connector.connector_scope.length > 0
                          && !includes(
                            fileToImport.metaData.mimetype,
                            connector.connector_scope,
                          ));
                      return (
                        <MenuItem
                          key={i}
                          value={connector.id}
                          disabled={disabled || !connector.active}
                        >
                          {connector.name}
                        </MenuItem>
                      );
                    })}
                  </Field>
                </DialogContent>
                <DialogActions>
                  <Button onClick={handleReset} disabled={isSubmitting}>
                    {t('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                  >
                    {t('Create')}
                  </Button>
                </DialogActions>
              </Dialog>
            </Form>
          )}
        </Formik>
      </div>
    );
  }
}

StixCoreObjectExternalReferencesLinesContainer.propTypes = {
  stixCoreObjectId: PropTypes.string,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  relay: PropTypes.object,
};

export const stixCoreObjectExternalReferencesLinesQuery = graphql`
  query StixCoreObjectExternalReferencesLinesQuery($count: Int!, $id: String!) {
    ...StixCoreObjectExternalReferencesLines_data
      @arguments(count: $count, id: $id)
  }
`;

const StixCoreObjectExternalReferencesLines = createPaginationContainer(
  StixCoreObjectExternalReferencesLinesContainer,
  {
    data: graphql`
      fragment StixCoreObjectExternalReferencesLines_data on Query
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 25 }
        id: { type: "String!" }
      ) {
        stixCoreObject(id: $id) {
          id
          externalReferences(first: $count)
            @connection(key: "Pagination_externalReferences") {
            edges {
              node {
                id
                source_name
                description
                url
                hash
                external_id
                jobs(first: 100) {
                  id
                  timestamp
                  connector {
                    id
                    name
                  }
                  messages {
                    timestamp
                    message
                  }
                  errors {
                    timestamp
                    message
                  }
                  status
                }
                connectors(onlyAlive: false) {
                  id
                  connector_type
                  name
                  active
                  updated_at
                }
                importFiles(first: 1000) {
                  edges {
                    node {
                      id
                      lastModified
                      ...FileLine_file
                      metaData {
                        mimetype
                      }
                    }
                  }
                }
              }
            }
          }
        }
        connectorsForImport {
          id
          name
          active
          connector_scope
          updated_at
        }
      }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.stixCoreObject.externalReferences;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count }, fragmentVariables) {
      return {
        count,
        id: fragmentVariables.id,
      };
    },
    query: stixCoreObjectExternalReferencesLinesQuery,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixCoreObjectExternalReferencesLines);

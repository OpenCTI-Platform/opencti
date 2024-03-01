import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { createPaginationContainer, graphql } from 'react-relay';
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
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import { ExpandLessOutlined, ExpandMoreOutlined, OpenInBrowserOutlined } from '@mui/icons-material';
import Slide from '@mui/material/Slide';
import { interval } from 'rxjs';
import { Link } from 'react-router-dom';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import inject18n from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';
import { commitMutation } from '../../../../relay/environment';
import AddExternalReferences from './AddExternalReferences';
import { externalReferenceMutationRelationDelete } from './AddExternalReferencesLines';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPLOAD } from '../../../../utils/hooks/useGranted';
import FileLine from '../../common/files/FileLine';
import FileUploader from '../../common/files/FileUploader';
import ExternalReferenceEnrichment from './ExternalReferenceEnrichment';
import { FIVE_SECONDS } from '../../../../utils/Time';
import ExternalReferencePopover from './ExternalReferencePopover';
import { isNotEmptyField } from '../../../../utils/utils';
import ItemIcon from '../../../../components/ItemIcon';

const interval$ = interval(FIVE_SECONDS);

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '-4px 0 0 0',
    padding: 0,
    borderRadius: 4,
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

class StixCoreRelationshipExternalReferencesLinesContainer extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayDialog: false,
      displayExternalLink: false,
      externalLink: null,
      removeExternalReference: null,
      removing: false,
      expanded: false,
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
        fromId: this.props.stixCoreRelationshipId,
        relationship_type: 'external-reference',
      },
      updater: (store) => {
        const entity = store.get(this.props.stixCoreRelationshipId);
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

  render() {
    const { t, classes, stixCoreRelationshipId, data } = this.props;
    const { expanded } = this.state;
    const externalReferencesEdges = data.stixCoreRelationship.externalReferences.edges;
    const expandable = externalReferencesEdges.length > 7;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('External references')}
        </Typography>
        <Security
          needs={[KNOWLEDGE_KNUPDATE]}
          placeholder={<div style={{ height: 29 }} />}
        >
          <AddExternalReferences
            stixCoreObjectOrStixCoreRelationshipId={stixCoreRelationshipId}
            stixCoreObjectOrStixCoreRelationshipReferences={
              data.stixCoreRelationship.externalReferences.edges
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
                  const isFileAttached = isNotEmptyField(
                    externalReference.fileId,
                  );
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
                  } else {
                    externalReferenceSecondary = t('No description');
                  }
                  if (externalReference.url) {
                    return (
                      <div key={externalReference.id}>
                        <ListItem
                          component={Link}
                          to={`/dashboard/analyses/external_references/${externalReference.id}`}
                          dense={true}
                          divider={true}
                          button={true}
                        >
                          <ListItemIcon>
                            <ItemIcon type="External-Reference" />
                          </ListItemIcon>
                          <ListItemText
                            primary={`${externalReference.source_name} ${externalReferenceId}`}
                            secondary={truncate(externalReferenceSecondary, 90)}
                          />
                          <ListItemSecondaryAction>
                            <Tooltip title={t('Browse the link')}>
                              <IconButton
                                onClick={this.handleOpenExternalLink.bind(
                                  this,
                                  externalReference.url,
                                )}
                                color="primary"
                                size="large"
                              >
                                <OpenInBrowserOutlined />
                              </IconButton>
                            </Tooltip>
                            {!isFileAttached && (
                              <Security needs={[KNOWLEDGE_KNUPLOAD]}>
                                <FileUploader
                                  entityId={externalReference.id}
                                  onUploadSuccess={() => this.props.relay.refetchConnection(200)
                                  }
                                />
                              </Security>
                            )}
                            {!isFileAttached && (
                              <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
                                <ExternalReferenceEnrichment
                                  externalReferenceId={externalReference.id}
                                />
                              </Security>
                            )}
                            <Security needs={[KNOWLEDGE_KNUPDATE]}>
                              <ExternalReferencePopover
                                id={externalReference.id}
                                isExternalReferenceAttachment={isFileAttached}
                                objectId={stixCoreRelationshipId}
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
                            {externalReference.importFiles.edges.map((file) => file?.node && (
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
                  }
                  return (
                    <div key={externalReference.id}>
                      <ListItem
                        component={Link}
                        to={`/dashboard/analyses/external_references/${externalReference.id}`}
                        dense={true}
                        divider={true}
                        button={true}
                      >
                        <ListItemIcon>
                          <ItemIcon type="External-Reference" />
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
                          {externalReference.importFiles.edges.map((file) => file?.node && (
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
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
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
          open={this.state.displayDialog}
          PaperProps={{ elevation: 1 }}
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
          open={this.state.displayExternalLink}
          PaperProps={{ elevation: 1 }}
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
      </div>
    );
  }
}

StixCoreRelationshipExternalReferencesLinesContainer.propTypes = {
  stixCoreRelationshipId: PropTypes.string,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const stixCoreRelationshipExternalReferencesLinesQuery = graphql`
  query StixCoreRelationshipExternalReferencesLinesQuery(
    $count: Int
    $id: String!
  ) {
    ...StixCoreRelationshipExternalReferencesLines_data
      @arguments(count: $count, id: $id)
  }
`;

const StixCoreRelationshipExternalReferencesLines = createPaginationContainer(
  StixCoreRelationshipExternalReferencesLinesContainer,
  {
    data: graphql`
      fragment StixCoreRelationshipExternalReferencesLines_data on Query
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 25 }
        id: { type: "String!" }
      ) {
        stixCoreRelationship(id: $id) {
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
                fileId
                entity_type
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
                importFiles(first: 500) {
                  edges {
                    node {
                      id
                      lastModified
                      ...FileLine_file
                      metaData {
                        mimetype
                        external_reference_id
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.stixCoreRelationship.externalReferences;
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
    query: stixCoreRelationshipExternalReferencesLinesQuery,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixCoreRelationshipExternalReferencesLines);

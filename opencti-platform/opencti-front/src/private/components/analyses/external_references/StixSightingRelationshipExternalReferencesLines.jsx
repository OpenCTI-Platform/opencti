import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { createPaginationContainer, graphql } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import { ExpandLessOutlined, ExpandMoreOutlined, OpenInBrowserOutlined } from '@mui/icons-material';
import Slide from '@mui/material/Slide';
import { interval } from 'rxjs';
import ListItem from '@mui/material/ListItem';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@common/button/IconButton';
import { Link } from 'react-router-dom';
import DialogTitle from '@mui/material/DialogTitle';
import { ListItemButton } from '@mui/material';
import inject18n from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';
import { commitMutation } from '../../../../relay/environment';
import AddExternalReferences from './AddExternalReferences';
import { externalReferenceMutationRelationDelete } from './AddExternalReferencesLines';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPLOAD } from '../../../../utils/hooks/useGranted';
import FileLine from '../../common/files/FileLine';
import { FIVE_SECONDS } from '../../../../utils/Time';
import FileUploader from '../../common/files/FileUploader';
import ExternalReferencePopover from './ExternalReferencePopover';
import ExternalReferenceEnrichment from './ExternalReferenceEnrichment';
import { isNotEmptyField } from '../../../../utils/utils';
import ItemIcon from '../../../../components/ItemIcon';
import { NO_DATA_WIDGET_MESSAGE } from '../../../../components/dashboard/WidgetNoData';

const interval$ = interval(FIVE_SECONDS);

const styles = (theme) => ({
  paper: {
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

class StixSightingRelationshipExternalReferencesLinesContainer extends Component {
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
        fromId: this.props.stixSightingRelationshipId,
        relationship_type: 'external-reference',
      },
      updater: (store) => {
        const entity = store.get(this.props.stixSightingRelationshipId);
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
    const { t, classes, stixSightingRelationshipId, data } = this.props;
    const { expanded } = this.state;
    const externalReferencesEdges = data.stixSightingRelationship.externalReferences.edges;
    const expandable = externalReferencesEdges.length > 7;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('External references')}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPDATE]} placeholder={<div style={{ height: 29 }} />}>
          <AddExternalReferences
            stixCoreObjectOrStixCoreRelationshipId={stixSightingRelationshipId}
            stixCoreObjectOrStixCoreRelationshipReferences={
              data.stixSightingRelationship.externalReferences.edges
            }
          />
        </Security>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} className="paper-for-grid" variant="outlined">
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
                          dense={true}
                          divider={true}
                          disablePadding
                          secondaryAction={(
                            <>
                              <Tooltip title={t('Browse the link')}>
                                <IconButton
                                  onClick={this.handleOpenExternalLink.bind(
                                    this,
                                    externalReference.url,
                                  )}
                                  color="primary"
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
                                  objectId={stixSightingRelationshipId}
                                  isExternalReferenceAttachment={isFileAttached}
                                  handleRemove={this.handleOpenDialog.bind(
                                    this,
                                    externalReferenceEdge,
                                  )}
                                  variant="inLine"
                                />
                              </Security>
                            </>
                          )}
                        >
                          <ListItemButton
                            component={Link}
                            to={`/dashboard/analyses/external_references/${externalReference.id}`}
                          >
                            <ListItemIcon>
                              <ItemIcon type="External-Reference" />
                            </ListItemIcon>
                            <ListItemText
                              primary={`${externalReference.source_name} ${externalReferenceId}`}
                              secondary={truncate(externalReferenceSecondary, 90)}
                            />
                          </ListItemButton>
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
                        dense={true}
                        divider={true}
                        secondaryAction={(
                          <>
                            <Security needs={[KNOWLEDGE_KNUPLOAD]}>
                              <FileUploader
                                entityId={externalReference.id}
                                onUploadSuccess={() => this.props.relay.refetchConnection(200)
                                }
                              />
                            </Security>
                            <Security needs={[KNOWLEDGE_KNUPDATE]}>
                              <ExternalReferencePopover
                                id={externalReference.id}
                                isExternalReferenceAttachment={isFileAttached}
                                handleRemove={this.handleOpenDialog.bind(
                                  this,
                                  externalReferenceEdge,
                                )}
                                variant="inLine"
                              />
                            </Security>
                          </>
                        )}
                      >
                        <ListItemButton
                          component={Link}
                          to={`/dashboard/analyses/external_references/${externalReference.id}`}
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
                        </ListItemButton>
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
                {t(NO_DATA_WIDGET_MESSAGE)}
              </span>
            </div>
          )}
          {expandable && (
            <IconButton
              size="small"
              onClick={this.handleToggleExpand.bind(this)}
              classes={{ root: classes.buttonExpand }}
            >
              {expanded ? (
                <ExpandLessOutlined />
              ) : (
                <ExpandMoreOutlined />
              )}
            </IconButton>
          )}
        </Paper>
        <Dialog
          slotProps={{ paper: { elevation: 1 } }}
          open={this.state.displayDialog}
          keepMounted={true}
          slots={{ transition: Transition }}
          onClose={this.handleCloseDialog.bind(this)}
        >
          <DialogTitle>
            {t('Are you sure?')}
          </DialogTitle>
          <DialogContent>
            <DialogContentText>
              {t('Do you want to remove this external reference?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              variant="secondary"
              onClick={this.handleCloseDialog.bind(this)}
              disabled={this.state.removing}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.handleRemoval.bind(this)}
              disabled={this.state.removing}
            >
              {t('Confirm')}
            </Button>
          </DialogActions>
        </Dialog>
        <Dialog
          slotProps={{ paper: { elevation: 1 } }}
          open={this.state.displayExternalLink}
          keepMounted={true}
          slots={{ transition: Transition }}
          onClose={this.handleCloseExternalLink.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to browse this external link?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button variant="secondary" onClick={this.handleCloseExternalLink.bind(this)}>
              {t('Cancel')}
            </Button>
            <Button
              button={true}
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

StixSightingRelationshipExternalReferencesLinesContainer.propTypes = {
  stixSightingRelationshipId: PropTypes.string,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const stixSightingRelationshipExternalReferencesLinesQuery = graphql`
  query StixSightingRelationshipExternalReferencesLinesQuery(
    $count: Int!
    $id: String!
  ) {
    ...StixSightingRelationshipExternalReferencesLines_data
      @arguments(count: $count, id: $id)
  }
`;

const StixSightingRelationshipExternalReferencesLines = createPaginationContainer(
  StixSightingRelationshipExternalReferencesLinesContainer,
  {
    data: graphql`
        fragment StixSightingRelationshipExternalReferencesLines_data on Query
        @argumentDefinitions(
          count: { type: "Int", defaultValue: 25 }
          id: { type: "String!" }
        ) {
          stixSightingRelationship(id: $id) {
            id
            externalReferences(first: $count)
              @connection(key: "Pagination_externalReferences") {
              edges {
                node {
                  id
                  source_name
                  entity_type
                  description
                  url
                  hash
                  fileId
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
      return (
        props.data && props.data.stixSightingRelationship.externalReferences
      );
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
    query: stixSightingRelationshipExternalReferencesLinesQuery,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixSightingRelationshipExternalReferencesLines);

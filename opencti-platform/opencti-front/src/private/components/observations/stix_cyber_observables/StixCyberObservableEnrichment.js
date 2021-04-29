import React, { useEffect } from 'react';
import { interval } from 'rxjs';
import * as R from 'ramda';
import { createRefetchContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import Tooltip from '@material-ui/core/Tooltip';
import IconButton from '@material-ui/core/IconButton';
import {
  CheckCircle,
  Delete,
  Extension,
  Refresh,
  Warning,
} from '@material-ui/icons';
import CircularProgress from '@material-ui/core/CircularProgress';
import { withStyles } from '@material-ui/core';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import List from '@material-ui/core/List';
import Paper from '@material-ui/core/Paper';
import { v4 as uuid } from 'uuid';
import { FIVE_SECONDS } from '../../../../utils/Time';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import Security, { KNOWLEDGE_KNENRICHMENT } from '../../../../utils/Security';

const interval$ = interval(FIVE_SECONDS);

const stixCyberObservableEnrichmentQuery = graphql`
  query StixCyberObservableEnrichmentQuery($id: String!) {
    stixCyberObservable(id: $id) {
      ...StixCyberObservableEnrichment_stixCyberObservable
    }
    connectorsForImport {
      ...StixCyberObservableEnrichment_connectorsForImport
    }
  }
`;

const stixCyberObservableEnrichmentDeleteMutation = graphql`
  mutation StixCyberObservableEnrichmentDeleteMutation($workId: ID!) {
    workEdit(id: $workId) {
      delete
    }
  }
`;

const stixCyberObservableEnrichmentAskEnrich = graphql`
  mutation StixCyberObservableEnrichmentMutation($id: ID!, $connectorId: ID!) {
    stixCyberObservableEdit(id: $id) {
      askEnrichment(connectorId: $connectorId) {
        id
      }
    }
  }
`;

const stixCyberObservableEnrichmentAskJob = graphql`
  mutation StixCyberObservableEnrichmentAskJobMutation(
    $fileName: ID!
    $connectorId: String
  ) {
    askJobImport(fileName: $fileName, connectorId: $connectorId) {
      id
    }
  }
`;

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '13px 0 0 0',
    padding: '10px 15px 10px 15px',
    borderRadius: 6,
  },
  nested: {
    paddingLeft: theme.spacing(4),
  },
  tooltip: {
    maxWidth: 600,
  },
});

const StixCyberObservableEnrichment = (props) => {
  const {
    stixCyberObservable,
    connectorsForImport,
    relay,
    classes,
    t,
    nsdt,
  } = props;
  const { id } = stixCyberObservable;
  const file = stixCyberObservable.importFiles
    && stixCyberObservable.importFiles.edges.length > 0
    ? stixCyberObservable.importFiles.edges[0].node
    : null;
  const askJob = (connectorId) => {
    commitMutation({
      mutation: stixCyberObservableEnrichmentAskJob,
      variables: { fileName: file.id, connectorId },
      onCompleted: () => {
        MESSAGING$.notifySuccess('Import successfully asked');
      },
    });
  };
  const askEnrich = (connectorId) => {
    commitMutation({
      mutation: stixCyberObservableEnrichmentAskEnrich,
      variables: { id, connectorId },
      onCompleted: () => relay.refetch({ id, entityType: stixCyberObservable.entity_type }),
    });
  };
  const deleteWork = (workId) => {
    commitMutation({
      mutation: stixCyberObservableEnrichmentDeleteMutation,
      variables: { workId },
      onCompleted: () => relay.refetch({ id, entityType: stixCyberObservable.entity_type }),
    });
  };
  useEffect(() => {
    const subscription = interval$.subscribe(() => {
      relay.refetch({
        id: stixCyberObservable.id,
        entityType: stixCyberObservable.entity_type,
      });
    });
    return () => {
      subscription.unsubscribe();
    };
  });
  const connectors = file && file.metaData
    ? R.filter(
      (n) => R.includes(file.metaData.mimetype, n.connector_scope)
            || n.connector_scope.length === 0,
      connectorsForImport,
    )
    : [];
  const allConnectors = R.sortBy(R.prop('name'), [
    ...stixCyberObservable.connectors,
    ...connectors,
  ]);
  return (
    <Paper classes={{ root: classes.paper }} elevation={2}>
      <List>
        {allConnectors.length > 0 ? (
          allConnectors.map((connector) => {
            const jobs = connector.connector_type === 'INTERNAL_IMPORT_FILE'
              ? R.filter(
                (n) => n.connector.id === connector.id,
                R.propOr([], 'works', file),
              )
              : R.filter(
                (n) => n.connector && n.connector.id === connector.id,
                R.propOr([], 'jobs', stixCyberObservable),
              );
            // eslint-disable-next-line max-len
            const isRefreshing = R.filter((node) => node.status !== 'complete', jobs).length > 0;
            return (
              <div key={connector.id}>
                <ListItem
                  divider={true}
                  classes={{ root: classes.item }}
                  button={true}
                >
                  <Tooltip
                    title={
                      connector.active
                        ? t('This connector is active')
                        : t('This connector is disconnected')
                    }
                  >
                    <ListItemIcon
                      style={{
                        color: connector.active ? '#4caf50' : '#f44336',
                      }}
                    >
                      <Extension />
                    </ListItemIcon>
                  </Tooltip>
                  <ListItemText primary={connector.name} />
                  <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
                    <ListItemSecondaryAction style={{ right: 0 }}>
                      <Tooltip
                        title={t('Refresh the knowledge using this connector')}
                      >
                        <IconButton
                          disabled={!connector.active || isRefreshing}
                          onClick={() => (connector.connector_type === 'INTERNAL_IMPORT_FILE'
                            ? askJob(connector.id)
                            : askEnrich(connector.id))
                          }
                        >
                          <Refresh />
                        </IconButton>
                      </Tooltip>
                    </ListItemSecondaryAction>
                  </Security>
                </ListItem>
                <List component="div" disablePadding={true}>
                  {jobs.map((work) => {
                    const isFail = work.errors.length > 0;
                    const messages = R.sortBy(R.prop('timestamp'), [
                      ...work.messages,
                      ...work.errors,
                    ]);
                    const messageToDisplay = (
                      <div>
                        {messages.length > 0
                          ? R.map(
                            (message) => (
                                <div key={message.message}>
                                  [{nsdt(message.timestamp)}] {message.message}
                                </div>
                            ),
                            messages,
                          )
                          : t(work.status)}
                      </div>
                    );
                    return (
                      <Tooltip
                        title={messageToDisplay}
                        key={uuid()}
                        classes={{ tooltip: classes.tooltip }}
                      >
                        <ListItem
                          dense={true}
                          button={true}
                          divider={true}
                          classes={{ root: classes.nested }}
                        >
                          <ListItemIcon>
                            {isFail && (
                              <Warning
                                style={{
                                  fontSize: 15,
                                  color: '#f44336',
                                }}
                              />
                            )}
                            {!isFail && work.status === 'complete' && (
                              <CheckCircle
                                style={{
                                  fontSize: 15,
                                  color: '#4caf50',
                                }}
                              />
                            )}
                            {((!isFail && work.status === 'wait')
                              || work.status === 'progress') && (
                              <CircularProgress
                                size={20}
                                thickness={2}
                                style={{ marginRight: 10 }}
                              />
                            )}
                          </ListItemIcon>
                          <ListItemText primary={nsdt(work.timestamp)} />
                          <ListItemSecondaryAction style={{ right: 0 }}>
                            <IconButton onClick={() => deleteWork(work.id)}>
                              <Delete />
                            </IconButton>
                          </ListItemSecondaryAction>
                        </ListItem>
                      </Tooltip>
                    );
                  })}
                </List>
              </div>
            );
          })
        ) : (
          <div>{t('No connectors for this type of observable')}</div>
        )}
      </List>
    </Paper>
  );
};

const StixCyberObservableEnrichmentFragment = createRefetchContainer(
  StixCyberObservableEnrichment,
  {
    stixCyberObservable: graphql`
      fragment StixCyberObservableEnrichment_stixCyberObservable on StixCyberObservable {
        id
        entity_type
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
        ... on Artifact {
          importFiles {
            edges {
              node {
                id
                name
                size
                metaData {
                  mimetype
                }
                works {
                  id
                  connector {
                    id
                    name
                  }
                  user {
                    name
                  }
                  received_time
                  tracking {
                    import_expected_number
                    import_processed_number
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
                  timestamp
                }
              }
            }
          }
        }
      }
    `,
    connectorsForImport: graphql`
      fragment StixCyberObservableEnrichment_connectorsForImport on Connector
      @relay(plural: true) {
        id
        name
        connector_type
        active
        connector_scope
        updated_at
      }
    `,
  },
  stixCyberObservableEnrichmentQuery,
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixCyberObservableEnrichmentFragment);

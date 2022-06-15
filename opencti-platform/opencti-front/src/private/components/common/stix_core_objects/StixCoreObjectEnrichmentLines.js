import React, { useEffect } from 'react';
import { interval } from 'rxjs';
import * as R from 'ramda';
import { graphql, createRefetchContainer } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import {
  CheckCircle,
  Delete,
  Extension,
  Refresh,
  Warning,
} from '@mui/icons-material';
import CircularProgress from '@mui/material/CircularProgress';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import List from '@mui/material/List';
import { v4 as uuid } from 'uuid';
import { FIVE_SECONDS } from '../../../../utils/Time';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import Security, { KNOWLEDGE_KNENRICHMENT } from '../../../../utils/Security';

const interval$ = interval(FIVE_SECONDS);

export const stixCoreObjectEnrichmentLinesQuery = graphql`
  query StixCoreObjectEnrichmentLinesQuery($id: String!) {
    stixCoreObject(id: $id) {
      ...StixCoreObjectEnrichmentLines_stixCoreObject
    }
    connectorsForImport {
      ...StixCoreObjectEnrichmentLines_connectorsForImport
    }
  }
`;

const stixCoreObjectEnrichmentLinesDeleteMutation = graphql`
  mutation StixCoreObjectEnrichmentLinesDeleteMutation($workId: ID!) {
    workEdit(id: $workId) {
      delete
    }
  }
`;

const stixCoreObjectEnrichmentLinesAskEnrich = graphql`
  mutation StixCoreObjectEnrichmentLinesMutation($id: ID!, $connectorId: ID!) {
    stixCoreObjectEdit(id: $id) {
      askEnrichment(connectorId: $connectorId) {
        id
      }
    }
  }
`;

const stixCoreObjectEnrichmentLinesAskJob = graphql`
  mutation StixCoreObjectEnrichmentLinesAskJobMutation(
    $fileName: ID!
    $connectorId: String
  ) {
    askJobImport(fileName: $fileName, connectorId: $connectorId) {
      id
    }
  }
`;

const styles = (theme) => ({
  noResult: {
    top: 10,
    left: 16,
    right: 0,
    position: 'absolute',
    color: theme.palette.text.primary,
    fontSize: 15,
    zIndex: -5,
  },
  gridContainer: {
    marginBottom: 20,
  },
  nested: {
    paddingLeft: theme.spacing(4),
  },
  tooltip: {
    maxWidth: 600,
  },
});

const StixCoreObjectEnrichment = (props) => {
  const { stixCoreObject, connectorsForImport, relay, classes, t, nsdt } = props;
  const { id } = stixCoreObject;
  const file = stixCoreObject.importFiles && stixCoreObject.importFiles.edges.length > 0
    ? stixCoreObject.importFiles.edges[0].node
    : null;
  const askJob = (connectorId) => {
    commitMutation({
      mutation: stixCoreObjectEnrichmentLinesAskJob,
      variables: { fileName: file.id, connectorId },
      onCompleted: () => {
        MESSAGING$.notifySuccess('Import successfully asked');
      },
    });
  };
  const askEnrich = (connectorId) => {
    commitMutation({
      mutation: stixCoreObjectEnrichmentLinesAskEnrich,
      variables: { id, connectorId },
      onCompleted: () => relay.refetch({ id, entityType: stixCoreObject.entity_type }),
    });
  };
  const deleteWork = (workId) => {
    commitMutation({
      mutation: stixCoreObjectEnrichmentLinesDeleteMutation,
      variables: { workId },
      onCompleted: () => relay.refetch({ id, entityType: stixCoreObject.entity_type }),
    });
  };
  useEffect(() => {
    const subscription = interval$.subscribe(() => {
      relay.refetch({
        id: stixCoreObject.id,
        entityType: stixCoreObject.entity_type,
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
    ...stixCoreObject.connectors,
    ...connectors,
  ]);
  return (
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
              R.propOr([], 'jobs', stixCoreObject),
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
                        size="large"
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
                        <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
                          <ListItemSecondaryAction style={{ right: 0 }}>
                            <IconButton
                              onClick={() => deleteWork(work.id)}
                              size="large"
                            >
                              <Delete />
                            </IconButton>
                          </ListItemSecondaryAction>
                        </Security>
                      </ListItem>
                    </Tooltip>
                  );
                })}
              </List>
            </div>
          );
        })
      ) : (
        <div className={classes.noResult}>
          {t('No connectors for this type of entity')}
        </div>
      )}
    </List>
  );
};

const StixCoreObjectEnrichmentLinesFragment = createRefetchContainer(
  StixCoreObjectEnrichment,
  {
    stixCoreObject: graphql`
      fragment StixCoreObjectEnrichmentLines_stixCoreObject on StixCoreObject {
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
      fragment StixCoreObjectEnrichmentLines_connectorsForImport on Connector
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
  stixCoreObjectEnrichmentLinesQuery,
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixCoreObjectEnrichmentLinesFragment);

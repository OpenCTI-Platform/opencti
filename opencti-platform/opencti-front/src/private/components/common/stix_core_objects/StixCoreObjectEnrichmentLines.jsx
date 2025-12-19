import React, { useEffect } from 'react';
import { interval } from 'rxjs';
import * as R from 'ramda';
import { createRefetchContainer, graphql } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@common/button/IconButton';
import { CheckCircleOutlined, DeleteOutlined, ExtensionOutlined, RefreshOutlined, WarningOutlined } from '@mui/icons-material';
import CircularProgress from '@mui/material/CircularProgress';
import withStyles from '@mui/styles/withStyles';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import List from '@mui/material/List';
import { v4 as uuid } from 'uuid';
import { ListItemButton } from '@mui/material';
import ListItem from '@mui/material/ListItem';
import { FIVE_SECONDS } from '../../../../utils/Time';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNENRICHMENT } from '../../../../utils/hooks/useGranted';

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
    color: theme.palette.text.primary,
    fontSize: 15,
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

const StixCoreObjectEnrichment = ({
  stixCoreObject,
  connectorsForImport,
  relay,
  classes,
  t,
  nsdt,
}) => {
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

          const isRefreshing = R.filter((node) => node.status !== 'complete', jobs).length > 0;
          return (
            <div key={connector.id}>
              <ListItem
                divider={true}
                disablePadding
                secondaryAction={(
                  <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
                    <div style={{ right: 0 }}>
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
                          <RefreshOutlined />
                        </IconButton>
                      </Tooltip>
                    </div>
                  </Security>
                )}
              >
                <ListItemButton classes={{ root: classes.item }}>
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
                      <ExtensionOutlined />
                    </ListItemIcon>
                  </Tooltip>
                  <ListItemText primary={connector.name} />
                </ListItemButton>
              </ListItem>
              <List component="div" disablePadding={true}>
                {jobs.map((work) => {
                  const isFail = work.errors && work.errors.length > 0;
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
                        divider={true}
                        disablePadding
                        secondaryAction={(
                          <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
                            <div style={{ right: 0 }}>
                              <IconButton
                                onClick={() => deleteWork(work.id)}
                              >
                                <DeleteOutlined />
                              </IconButton>
                            </div>
                          </Security>
                        )}
                      >
                        <ListItemButton classes={{ root: classes.nested }}>
                          <ListItemIcon>
                            {isFail && (
                              <WarningOutlined
                                style={{
                                  fontSize: 15,
                                  color: '#f44336',
                                }}
                              />
                            )}
                            {!isFail && work.status === 'complete' && (
                              <CheckCircleOutlined
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
                        </ListItemButton>
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

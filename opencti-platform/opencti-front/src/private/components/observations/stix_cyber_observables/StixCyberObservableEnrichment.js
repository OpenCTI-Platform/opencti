import React, { useEffect } from 'react';
import { interval } from 'rxjs';
import {
  pipe, propOr, compose, filter, map,
} from 'ramda';
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
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import Security, { KNOWLEDGE_KNENRICHMENT } from '../../../../utils/Security';

const interval$ = interval(FIVE_SECONDS);

const StixCyberObservableEnrichmentQuery = graphql`
  query StixCyberObservableEnrichmentQuery($id: String!) {
    stixCyberObservable(id: $id) {
      ...StixCyberObservableEnrichment_stixCyberObservable
    }
  }
`;

const StixCyberObservableEnrichmentDeleteMutation = graphql`
  mutation StixCyberObservableEnrichmentDeleteMutation($workId: ID!) {
    workEdit(id: $workId) {
      delete
    }
  }
`;

const StixCyberObservableEnrichmentAskEnrich = graphql`
  mutation StixCyberObservableEnrichmentMutation($id: ID!, $connectorId: ID!) {
    stixCyberObservableEdit(id: $id) {
      askEnrichment(connectorId: $connectorId) {
        id
      }
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
    stixCyberObservable, relay, classes, t, nsdt,
  } = props;
  const { id } = stixCyberObservable;
  const askEnrich = (connectorId) => {
    commitMutation({
      mutation: StixCyberObservableEnrichmentAskEnrich,
      variables: { id, connectorId },
      onCompleted: () => relay.refetch({ id, entityType: stixCyberObservable.entity_type }),
    });
  };
  const deleteWork = (workId) => {
    commitMutation({
      mutation: StixCyberObservableEnrichmentDeleteMutation,
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
  return (
    <Paper classes={{ root: classes.paper }} elevation={2}>
      <List>
        {stixCyberObservable.connectors.length > 0 ? (
          stixCyberObservable.connectors.map((connector) => {
            const jobs = pipe(
              propOr([], 'jobs'),
              filter((n) => n.connector && n.connector.id === connector.id),
            )(stixCyberObservable);
            // eslint-disable-next-line max-len
            const isRefreshing = filter((node) => node.status !== 'complete', jobs).length > 0;
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
                          onClick={() => askEnrich(connector.id)}
                        >
                          <Refresh />
                        </IconButton>
                      </Tooltip>
                    </ListItemSecondaryAction>
                  </Security>
                </ListItem>
                <List component="div" disablePadding={true}>
                  {jobs.map((work) => {
                    const messageToDisplay = (
                      <div>
                        {work.messages.length > 0
                          ? map(
                            (message) => (
                                <div>
                                  [${nsdt(message.timestamp)}] {message.message}
                                </div>
                            ),
                            work.messages,
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
                            {(work.status === 'error'
                              || work.status === 'partial') && (
                              <Warning
                                style={{
                                  fontSize: 15,
                                  color: '#f44336',
                                }}
                              />
                            )}
                            {work.status === 'complete' && (
                              <CheckCircle
                                style={{
                                  fontSize: 15,
                                  color: '#4caf50',
                                }}
                              />
                            )}
                            {(work.status === 'wait'
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
          status
        }
        connectors(onlyAlive: false) {
          id
          name
          active
          updated_at
        }
      }
    `,
  },
  StixCyberObservableEnrichmentQuery,
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixCyberObservableEnrichmentFragment);

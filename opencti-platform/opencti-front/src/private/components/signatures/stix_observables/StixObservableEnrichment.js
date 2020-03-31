import React, { useEffect } from 'react';
import { interval } from 'rxjs';
import {
  pipe, propOr, compose, filter, last, join,
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

const StixObservableEnrichmentQuery = graphql`
  query StixObservableEnrichmentQuery($id: String!) {
    stixObservable(id: $id) {
      ...StixObservableEnrichment_stixObservable
    }
  }
`;

const StixObservableEnrichmentDeleteMutation = graphql`
  mutation StixObservableEnrichmentDeleteMutation($workId: ID!) {
    deleteWork(id: $workId)
  }
`;

const StixObservableEnrichmentAskEnrich = graphql`
  mutation StixObservableEnrichmentMutation($id: ID!, $connectorId: ID!) {
    stixObservableEdit(id: $id) {
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
});

const StixObservableEnrichment = (props) => {
  const {
    stixObservable, relay, classes, t, nsdt,
  } = props;
  const { id } = stixObservable;
  const askEnrich = (connectorId) => {
    commitMutation({
      mutation: StixObservableEnrichmentAskEnrich,
      variables: { id, connectorId },
      onCompleted: () => relay.refetch({ id, entityType: stixObservable.entity_type }),
    });
  };
  const deleteWork = (workId) => {
    commitMutation({
      mutation: StixObservableEnrichmentDeleteMutation,
      variables: { workId },
      onCompleted: () => relay.refetch({ id, entityType: stixObservable.entity_type }),
    });
  };
  useEffect(() => {
    const subscription = interval$.subscribe(() => {
      relay.refetch({
        id: stixObservable.id,
        entityType: stixObservable.entity_type,
      });
    });
    return () => {
      subscription.unsubscribe();
    };
  });
  return (
    <Paper classes={{ root: classes.paper }} elevation={2}>
      <List>
        {stixObservable.connectors.length > 0 ? (
          stixObservable.connectors.map((connector) => {
            const jobs = pipe(
              propOr([], 'jobs'),
              filter((n) => n.connector.id === connector.id),
            )(stixObservable);
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
                    const message = join(
                      ' | ',
                      propOr([], 'messages', last(propOr([], 'jobs', work))),
                    );
                    return (
                      <Tooltip title={message} key={uuid()}>
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
                            {work.status === 'progress' && (
                              <CircularProgress
                                size={20}
                                thickness={2}
                                style={{ marginRight: 10 }}
                              />
                            )}
                          </ListItemIcon>
                          <ListItemText primary={nsdt(work.created_at)} />
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

const StixObservableEnrichmentFragment = createRefetchContainer(
  StixObservableEnrichment,
  {
    stixObservable: graphql`
      fragment StixObservableEnrichment_stixObservable on StixObservable {
        id
        entity_type
        jobs(first: 100) {
          id
          created_at
          connector {
            id
            name
          }
          jobs {
            messages
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
  StixObservableEnrichmentQuery,
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixObservableEnrichmentFragment);

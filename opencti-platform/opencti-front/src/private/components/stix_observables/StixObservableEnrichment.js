import React, { useEffect } from 'react';
import { interval } from 'rxjs';
import { compose, filter } from 'ramda';
import { createRefetchContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import Tooltip from '@material-ui/core/Tooltip';
import IconButton from '@material-ui/core/IconButton';
import {
  Refresh,
  Extension,
  Warning,
  CheckCircle,
  Delete,
} from '@material-ui/icons';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import CircularProgress from '@material-ui/core/CircularProgress';
import { withStyles } from '@material-ui/core';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import List from '@material-ui/core/List';
import Paper from '@material-ui/core/Paper';
import uuid from 'uuid/v4';
import { FIVE_SECONDS } from '../../../utils/Time';
import { commitMutation } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import StixObservableHeader from './StixObservableHeader';
import StixObservableEnrichmentEntities from './StixObservableEnrichmentEntities';

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
    minHeight: '100%',
    margin: '10px 0 0 0',
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
    return function cleanup() {
      subscription.unsubscribe();
    };
  });
  return (
    <div className={classes.container}>
      <StixObservableHeader stixObservable={stixObservable} />
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={9}>
          <StixObservableEnrichmentEntities entityId={stixObservable.id} />
        </Grid>
        <Grid item={true} xs={3}>
          <Typography variant="h4" gutterBottom={true}>
            {t('Enabled enrichment connectors')}
          </Typography>
          <Paper classes={{ root: classes.paper }} elevation={2}>
            <List>
              {stixObservable.connectors.map((connector) => {
                const isRefreshing = filter(
                  (node) => node.status !== 'complete',
                  stixObservable.jobs,
                ).length > 0;
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
                      <ListItemSecondaryAction>
                        <Tooltip
                          title={t(
                            'Refresh the enrichment using this connector',
                          )}
                        >
                          {isRefreshing ? (
                            <CircularProgress
                              size={25}
                              thickness={2}
                              style={{ marginRight: 10 }}
                            />
                          ) : (
                            <IconButton
                              disabled={!connector.active}
                              onClick={() => askEnrich(connector.id)}
                            >
                              <Refresh />
                            </IconButton>
                          )}
                        </Tooltip>
                      </ListItemSecondaryAction>
                    </ListItem>
                    <List component="div" disablePadding={true}>
                      {stixObservable.jobs
                        && stixObservable.jobs.map((work) => (
                          <ListItem
                            key={uuid()}
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
                            <ListItemSecondaryAction>
                              <IconButton
                                disabled={!connector.active}
                                onClick={() => deleteWork(work.id)}
                              >
                                <Delete />
                              </IconButton>
                            </ListItemSecondaryAction>
                          </ListItem>
                        ))}
                    </List>
                  </div>
                );
              })}
            </List>
          </Paper>
        </Grid>
      </Grid>
    </div>
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
            name
          }
          status
        }
        connectors(onlyAlive: false) {
          id
          name
          active
          updated_at
        }
        ...StixObservableHeader_stixObservable
      }
    `,
  },
  StixObservableEnrichmentQuery,
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixObservableEnrichmentFragment);

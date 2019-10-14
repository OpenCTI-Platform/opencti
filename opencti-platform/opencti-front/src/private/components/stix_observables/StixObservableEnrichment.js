import React, { useEffect } from 'react';
import { interval } from 'rxjs';
import { createRefetchContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import Tooltip from '@material-ui/core/Tooltip';
import IconButton from '@material-ui/core/IconButton';
import { CheckCircle, Warning, PlayCircleFilledWhite } from '@material-ui/icons';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import CircularProgress from '@material-ui/core/CircularProgress';
import { TEN_SECONDS } from '../../../utils/Time';
import { commitMutation } from '../../../relay/environment';

const interval$ = interval(TEN_SECONDS);

const StixObservableEnrichmentQuery = graphql`
  query StixObservableEnrichmentQuery($id: String!) {
    stixObservable(id: $id) {
        ...StixObservableEnrichment_stixObservable
    }
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

const StixObservableEnrichment = (props) => {
  const { stixObservable, relay } = props;
  const askEnrich = (connectorId) => {
    const { id } = stixObservable;
    commitMutation({
      mutation: StixObservableEnrichmentAskEnrich,
      variables: { id, connectorId },
      onCompleted: () => relay.refetch({ id, entityType: stixObservable.entity_type }),
    });
  };
  useEffect(() => {
    const subscription = interval$.subscribe(() => {
      relay.refetch({ id: stixObservable.id, entityType: stixObservable.entity_type });
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  });
  return <div>
      <Grid container={true} spacing={3}>
          <Grid item={true} xs={6}>
          {stixObservable.connectors.map(conn => <React.Fragment key={conn.id}>
                <div style={{ float: 'left' }}>
                    <Typography variant="h2" style={{ paddingTop: 15 }} gutterBottom={true}>
                        {conn.name}
                    </Typography>
                </div>
                <div style={{ float: 'left' }}>
                    <Tooltip title="Ask enrichment" aria-label="Ask enrichment">
                        <IconButton disabled={!conn.active} onClick={() => askEnrich(conn.id)}
                                    aria-haspopup="true" color="primary">
                            <PlayCircleFilledWhite/>
                        </IconButton>
                    </Tooltip>
                </div>
            </React.Fragment>)}
          </Grid>
      </Grid>
      <div>
          {stixObservable.jobs.edges.map((data) => {
            const { node } = data;
            return <div key={node.id}>
                <Tooltip title={node.work_message} aria-label={node.work_message}>
                  <span>
                      {node.work_status === 'error'
                      && <Warning style={{ fontSize: 10, marginRight: 10, color: 'red' }}/>}
                      {node.work_status === 'complete'
                      && <CheckCircle style={{ fontSize: 10, marginRight: 10, color: 'green' }}/>}
                      {node.work_status === 'progress'
                      && <CircularProgress size={10} thickness={2} style={{ marginRight: 10 }} />}
                  </span>
                </Tooltip>
                {node.connector.name} / {node.updated_at}
            </div>;
          })}
      </div>
  </div>;
};

const StixObservableEnrichmentFragment = createRefetchContainer(
  StixObservableEnrichment,
  {
    stixObservable: graphql`
      fragment StixObservableEnrichment_stixObservable on StixObservable {
          id
          entity_type
          jobs(first: 100, orderBy: updated_at, orderMode: desc) @connection(key: "Pagination_jobs") {
            edges {
              node {
                id
                connector {
                  name
                }
                updated_at
                work_message
                work_status
              }
            }
          }
          connectors(onlyAlive: false) {
              id
              name
              active
          }
        }
    `,
  },
  StixObservableEnrichmentQuery,
);

export default StixObservableEnrichmentFragment;

import React, { useEffect } from 'react';
import { interval } from 'rxjs';
import { createRefetchContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { TEN_SECONDS } from '../../../utils/Time';

const interval$ = interval(TEN_SECONDS);

const StixObservableEnrichmentQuery = graphql`
  query StixObservableEnrichmentQuery($id: String!) {
    stixObservable(id: $id) {
        ...StixObservableEnrichment_stixObservable
    }
  }
`;

const StixObservableEnrichment = (props) => {
  const { stixObservable, relay } = props;
  useEffect(() => {
    const subscription = interval$.subscribe(() => {
      relay.refetch({ id: stixObservable.id, entityType: stixObservable.entity_type });
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  });
  return <div>
      <div>
          {stixObservable.connectors.map((conn) => {
            console.log(conn);
            return <div key={conn.id}>{conn.name} / {conn.active}</div>;
          })}
      </div>
      <div>
          {stixObservable.jobs.edges.map((data) => {
            const { node } = data;
            return <div key={node.id}>{node.work_status} / {node.work_message}</div>;
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
          jobs(first: 100) @connection(key: "Pagination_jobs") {
            edges {
              node {
                id
                connector {
                  name
                }
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

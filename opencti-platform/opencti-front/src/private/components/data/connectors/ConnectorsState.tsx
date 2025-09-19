import { graphql, usePreloadedQuery } from 'react-relay';
import type { PreloadedQuery } from 'react-relay';
import React from 'react';
import type { ConnectorsStateQuery } from './__generated__/ConnectorsStateQuery.graphql';

export const connectorsStateQuery = graphql`
  query ConnectorsStateQuery {
    connectors {
      id
      active
      auto
      manager_current_status
      manager_requested_status
    }
    rabbitMQMetrics {
      queues {
        name
        messages
        messages_ready
        messages_unacknowledged
        consumers
        idle_since
        message_stats {
          ack
          ack_details {
            rate
          }
        }
      }
    }
  }
`;

interface ConnectorsStateProps {
  queryRef: PreloadedQuery<ConnectorsStateQuery>;
  children: ({ data }: { data: ConnectorsStateQuery['response'] }) => React.ReactNode;
}

const ConnectorsState: React.FC<ConnectorsStateProps> = ({ queryRef, children }) => {
  const data = usePreloadedQuery(connectorsStateQuery, queryRef);

  return children({ data });
};

export default ConnectorsState;

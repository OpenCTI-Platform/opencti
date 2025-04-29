import { graphql, useFragment } from 'react-relay';
import React from 'react';
import { PirOverviewHistoryFragment$key } from '@components/pir/__generated__/PirOverviewHistoryFragment.graphql';

const pirHistoryFragment = graphql`
  fragment PirOverviewHistoryFragment on Query {
    logs(
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      search: $search
    ) {
      edges {
        node {
          id
          event_type
          event_scope
          timestamp
          user {
            name
          }
          context_data {
            message
            commit
            external_references {
              id
              source_name
              external_id
              url
              description
            }
          }
        }
      }
    }
  }
`;

interface PirOverviewProps {
  data: PirOverviewHistoryFragment$key
}

const PirOverview = ({ data }: PirOverviewProps) => {
  const { logs } = useFragment(pirHistoryFragment, data);
  console.log(logs);

  return (
    <div>pouet</div>
  );
};

export default PirOverview;

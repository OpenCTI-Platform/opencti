import React from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { IngestionFeedsQuery } from './__generated__/IngestionFeedsQuery.graphql';
import { IngestionFeedsFormsQuery } from './__generated__/IngestionFeedsFormsQuery.graphql';

// All built-in ingestion instances (INGESTION capability), fetched in one
// round-trip for the deployed tab and the available tab counters.
export const ingestionFeedsQuery = graphql`
  query IngestionFeedsQuery($first: Int) {
    synchronizers(first: $first) {
      pageInfo {
        globalCount
      }
      edges {
        node {
          id
          name
          uri
          stream_id
          running
          current_state_date
          queue_messages
          user {
            id
            name
          }
        }
      }
    }
    ingestionRsss(first: $first) {
      pageInfo {
        globalCount
      }
      edges {
        node {
          id
          name
          description
          uri
          scheduling_period
          ingestion_running
          current_state_date
          last_execution_date
          created_at
          updated_at
          user {
            id
            name
          }
        }
      }
    }
    ingestionTaxiis(first: $first) {
      pageInfo {
        globalCount
      }
      edges {
        node {
          id
          name
          description
          uri
          collection
          version
          scheduling_period
          ingestion_running
          last_execution_date
          created_at
          updated_at
          user {
            id
            name
          }
        }
      }
    }
    ingestionTaxiiCollections(first: $first) {
      pageInfo {
        globalCount
      }
      edges {
        node {
          id
          name
          description
          ingestion_running
          created_at
          updated_at
          user {
            id
            name
          }
        }
      }
    }
    ingestionCsvs(first: $first) {
      pageInfo {
        globalCount
      }
      edges {
        node {
          id
          name
          description
          uri
          scheduling_period
          ingestion_running
          current_state_date
          last_execution_date
          created_at
          updated_at
          user {
            id
            name
          }
        }
      }
    }
    ingestionJsons(first: $first) {
      pageInfo {
        globalCount
      }
      edges {
        node {
          id
          name
          description
          uri
          verb
          scheduling_period
          ingestion_running
          last_execution_date
          created_at
          updated_at
          user {
            id
            name
          }
        }
      }
    }
  }
`;

// Form intakes live behind a different capability (knowledge update / import),
// hence the dedicated query so a partial grant does not fail the whole fetch.
export const ingestionFeedsFormsQuery = graphql`
  query IngestionFeedsFormsQuery($first: Int) {
    forms(first: $first) {
      pageInfo {
        globalCount
      }
      edges {
        node {
          id
          name
          description
          active
          created_at
          updated_at
        }
      }
    }
  }
`;

export type IngestionFeedsData = IngestionFeedsQuery['response'];
export type IngestionFeedsFormsData = IngestionFeedsFormsQuery['response'];

interface IngestionFeedsProps {
  queryRef: PreloadedQuery<IngestionFeedsQuery>;
  children: ({ data }: { data: IngestionFeedsData }) => React.ReactNode;
}

export const IngestionFeeds: React.FC<IngestionFeedsProps> = ({ queryRef, children }) => {
  const data = usePreloadedQuery(ingestionFeedsQuery, queryRef);
  return children({ data });
};

interface IngestionFeedsFormsProps {
  queryRef: PreloadedQuery<IngestionFeedsFormsQuery>;
  children: ({ data }: { data: IngestionFeedsFormsData }) => React.ReactNode;
}

export const IngestionFeedsForms: React.FC<IngestionFeedsFormsProps> = ({ queryRef, children }) => {
  const data = usePreloadedQuery(ingestionFeedsFormsQuery, queryRef);
  return children({ data });
};

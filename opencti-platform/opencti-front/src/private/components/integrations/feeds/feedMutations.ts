import { graphql } from 'react-relay';
import type { GraphQLTaggedNode } from 'react-relay';
import { BuiltInIntegrationKind } from '@components/integrations/available/builtInIntegrations';

const feedSyncStartMutation = graphql`
  mutation feedMutationsSyncStartMutation($id: ID!) {
    synchronizerStart(id: $id) {
      id
      running
    }
  }
`;

const feedSyncStopMutation = graphql`
  mutation feedMutationsSyncStopMutation($id: ID!) {
    synchronizerStop(id: $id) {
      id
      running
    }
  }
`;

const feedSyncDeleteMutation = graphql`
  mutation feedMutationsSyncDeleteMutation($id: ID!) {
    synchronizerEdit(id: $id) {
      delete
    }
  }
`;

const feedRssToggleMutation = graphql`
  mutation feedMutationsRssToggleMutation($id: ID!, $input: [EditInput!]!) {
    ingestionRssFieldPatch(id: $id, input: $input) {
      id
      ingestion_running
    }
  }
`;

const feedRssDeleteMutation = graphql`
  mutation feedMutationsRssDeleteMutation($id: ID!) {
    ingestionRssDelete(id: $id)
  }
`;

const feedTaxiiToggleMutation = graphql`
  mutation feedMutationsTaxiiToggleMutation($id: ID!, $input: [EditInput!]!) {
    ingestionTaxiiFieldPatch(id: $id, input: $input) {
      id
      ingestion_running
    }
  }
`;

const feedTaxiiDeleteMutation = graphql`
  mutation feedMutationsTaxiiDeleteMutation($id: ID!) {
    ingestionTaxiiDelete(id: $id)
  }
`;

const feedTaxiiCollectionToggleMutation = graphql`
  mutation feedMutationsTaxiiCollectionToggleMutation($id: ID!, $input: [EditInput!]!) {
    ingestionTaxiiCollectionFieldPatch(id: $id, input: $input) {
      id
      ingestion_running
    }
  }
`;

const feedTaxiiCollectionDeleteMutation = graphql`
  mutation feedMutationsTaxiiCollectionDeleteMutation($id: ID!) {
    ingestionTaxiiCollectionDelete(id: $id)
  }
`;

const feedCsvToggleMutation = graphql`
  mutation feedMutationsCsvToggleMutation($id: ID!, $input: [EditInput!]!) {
    ingestionCsvFieldPatch(id: $id, input: $input) {
      id
      ingestion_running
    }
  }
`;

const feedCsvDeleteMutation = graphql`
  mutation feedMutationsCsvDeleteMutation($id: ID!) {
    ingestionCsvDelete(id: $id)
  }
`;

const feedJsonToggleMutation = graphql`
  mutation feedMutationsJsonToggleMutation($id: ID!, $input: [EditInput!]!) {
    ingestionJsonFieldPatch(id: $id, input: $input) {
      id
      ingestion_running
    }
  }
`;

const feedJsonDeleteMutation = graphql`
  mutation feedMutationsJsonDeleteMutation($id: ID!) {
    ingestionJsonDelete(id: $id)
  }
`;

const feedFormToggleMutation = graphql`
  mutation feedMutationsFormToggleMutation($id: ID!, $input: [EditInput!]!) {
    formFieldPatch(id: $id, input: $input) {
      id
      active
    }
  }
`;

const feedFormDeleteMutation = graphql`
  mutation feedMutationsFormDeleteMutation($id: ID!) {
    formDelete(id: $id)
  }
`;

export interface FeedMutationsConfig {
  // Field patched to start/pause the instance; sync uses dedicated mutations.
  toggleField?: 'ingestion_running' | 'active';
  toggleMutation?: GraphQLTaggedNode;
  startMutation?: GraphQLTaggedNode;
  stopMutation?: GraphQLTaggedNode;
  deleteMutation: GraphQLTaggedNode;
}

export const FEED_MUTATIONS: Record<BuiltInIntegrationKind, FeedMutationsConfig> = {
  sync: {
    startMutation: feedSyncStartMutation,
    stopMutation: feedSyncStopMutation,
    deleteMutation: feedSyncDeleteMutation,
  },
  taxii: {
    toggleField: 'ingestion_running',
    toggleMutation: feedTaxiiToggleMutation,
    deleteMutation: feedTaxiiDeleteMutation,
  },
  'taxii-push': {
    toggleField: 'ingestion_running',
    toggleMutation: feedTaxiiCollectionToggleMutation,
    deleteMutation: feedTaxiiCollectionDeleteMutation,
  },
  rss: {
    toggleField: 'ingestion_running',
    toggleMutation: feedRssToggleMutation,
    deleteMutation: feedRssDeleteMutation,
  },
  csv: {
    toggleField: 'ingestion_running',
    toggleMutation: feedCsvToggleMutation,
    deleteMutation: feedCsvDeleteMutation,
  },
  json: {
    toggleField: 'ingestion_running',
    toggleMutation: feedJsonToggleMutation,
    deleteMutation: feedJsonDeleteMutation,
  },
  form: {
    toggleField: 'active',
    toggleMutation: feedFormToggleMutation,
    deleteMutation: feedFormDeleteMutation,
  },
};

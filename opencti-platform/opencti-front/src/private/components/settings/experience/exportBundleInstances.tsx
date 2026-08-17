import { graphql } from 'react-relay';
import type { GraphQLTaggedNode } from 'react-relay';
import type { ExportBundleWorkspacesQuery$data } from './__generated__/ExportBundleWorkspacesQuery.graphql';
import type { ExportBundlePlaybooksQuery$data } from './__generated__/ExportBundlePlaybooksQuery.graphql';
import type { ExportBundleFormsQuery$data } from './__generated__/ExportBundleFormsQuery.graphql';
import type { ExportBundleCustomViewsQuery$data } from './__generated__/ExportBundleCustomViewsQuery.graphql';
import type { ExportBundleIngestionCsvsQuery$data } from './__generated__/ExportBundleIngestionCsvsQuery.graphql';
import type { ExportBundleIngestionJsonsQuery$data } from './__generated__/ExportBundleIngestionJsonsQuery.graphql';
import type { ExportBundleIngestionRsssQuery$data } from './__generated__/ExportBundleIngestionRsssQuery.graphql';
import type { ExportBundleIngestionTaxiisQuery$data } from './__generated__/ExportBundleIngestionTaxiisQuery.graphql';

export interface InstanceItem {
  id: string;
  name: string;
}

export interface InstanceConnection {
  edges: ReadonlyArray<{ node: InstanceItem | null } | null> | null;
  pageInfo: { endCursor: string | null; hasNextPage: boolean; globalCount: number | null };
}

export interface ExportInstanceConfig {
  entityType: string;
  label: string;
  group?: string;
  query: GraphQLTaggedNode;
  extraVariables?: Record<string, unknown>;
  extractConnection: (data: unknown) => InstanceConnection | null | undefined;
}

const dashboardsFilters = {
  mode: 'and',
  filters: [{ key: 'type', values: ['dashboard'], mode: 'or', operator: 'eq' }],
  filterGroups: [],
};

const workspacesQuery = graphql`
  query ExportBundleWorkspacesQuery($search: String, $count: Int!, $cursor: ID, $filters: FilterGroup) {
    workspaces(search: $search, first: $count, after: $cursor, orderBy: name, orderMode: asc, filters: $filters) {
      edges { node { id name } }
      pageInfo { endCursor hasNextPage globalCount }
    }
  }
`;

const playbooksQuery = graphql`
  query ExportBundlePlaybooksQuery($search: String, $count: Int!, $cursor: ID) {
    playbooks(search: $search, first: $count, after: $cursor) {
      edges { node { id name } }
      pageInfo { endCursor hasNextPage globalCount }
    }
  }
`;

const formsQuery = graphql`
  query ExportBundleFormsQuery($search: String, $count: Int!, $cursor: ID) {
    forms(search: $search, first: $count, after: $cursor) {
      edges { node { id name } }
      pageInfo { endCursor hasNextPage globalCount }
    }
  }
`;

const customViewsQuery = graphql`
  query ExportBundleCustomViewsQuery($search: String, $count: Int!, $cursor: ID) {
    customViews(search: $search, first: $count, after: $cursor) {
      edges { node { id name } }
      pageInfo { endCursor hasNextPage globalCount }
    }
  }
`;

const ingestionCsvsQuery = graphql`
  query ExportBundleIngestionCsvsQuery($search: String, $count: Int!, $cursor: ID) {
    ingestionCsvs(search: $search, first: $count, after: $cursor) {
      edges { node { id name } }
      pageInfo { endCursor hasNextPage globalCount }
    }
  }
`;

const ingestionJsonsQuery = graphql`
  query ExportBundleIngestionJsonsQuery($search: String, $count: Int!, $cursor: ID) {
    ingestionJsons(search: $search, first: $count, after: $cursor) {
      edges { node { id name } }
      pageInfo { endCursor hasNextPage globalCount }
    }
  }
`;

const ingestionRsssQuery = graphql`
  query ExportBundleIngestionRsssQuery($search: String, $count: Int!, $cursor: ID) {
    ingestionRsss(search: $search, first: $count, after: $cursor) {
      edges { node { id name } }
      pageInfo { endCursor hasNextPage globalCount }
    }
  }
`;

const ingestionTaxiisQuery = graphql`
  query ExportBundleIngestionTaxiisQuery($search: String, $count: Int!, $cursor: ID) {
    ingestionTaxiis(search: $search, first: $count, after: $cursor) {
      edges { node { id name } }
      pageInfo { endCursor hasNextPage globalCount }
    }
  }
`;

export const EXPORT_INSTANCE_CONFIGS: ExportInstanceConfig[] = [
  {
    entityType: 'Playbook',
    label: 'Playbooks',
    group: 'Ingestion',
    query: playbooksQuery,
    extractConnection: (data) => (data as ExportBundlePlaybooksQuery$data)?.playbooks as unknown as InstanceConnection,
  },
  {
    entityType: 'Form',
    label: 'Forms',
    group: 'Ingestion',
    query: formsQuery,
    extractConnection: (data) => (data as ExportBundleFormsQuery$data)?.forms as unknown as InstanceConnection,
  },
  {
    entityType: 'Workspace',
    label: 'Custom Dashboards',
    query: workspacesQuery,
    extraVariables: { filters: dashboardsFilters },
    extractConnection: (data) => (data as ExportBundleWorkspacesQuery$data)?.workspaces as unknown as InstanceConnection,
  },
  {
    entityType: 'CustomView',
    label: 'Custom Views',
    query: customViewsQuery,
    extractConnection: (data) => (data as ExportBundleCustomViewsQuery$data)?.customViews as unknown as InstanceConnection,
  },
  {
    entityType: 'IngestionCsv',
    label: 'CSV Feeds',
    group: 'Feeds',
    query: ingestionCsvsQuery,
    extractConnection: (data) => (data as ExportBundleIngestionCsvsQuery$data)?.ingestionCsvs as unknown as InstanceConnection,
  },
  {
    entityType: 'IngestionTaxii',
    label: 'Taxii Feeds',
    group: 'Feeds',
    query: ingestionTaxiisQuery,
    extractConnection: (data) => (data as ExportBundleIngestionTaxiisQuery$data)?.ingestionTaxiis as unknown as InstanceConnection,
  },
  {
    entityType: 'IngestionJson',
    label: 'JSON Feeds',
    group: 'Feeds',
    query: ingestionJsonsQuery,
    extractConnection: (data) => (data as ExportBundleIngestionJsonsQuery$data)?.ingestionJsons as unknown as InstanceConnection,
  },
  {
    entityType: 'IngestionRss',
    label: 'RSS Feeds',
    group: 'Feeds',
    query: ingestionRsssQuery,
    extractConnection: (data) => (data as ExportBundleIngestionRsssQuery$data)?.ingestionRsss as unknown as InstanceConnection,
  },
];

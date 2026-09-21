import { graphql } from 'react-relay';

export const workspacesQuery = graphql`
  query ExportBundleWorkspacesQuery($search: String, $count: Int!, $cursor: ID, $filters: FilterGroup) {
    workspaces(search: $search, first: $count, after: $cursor, orderBy: name, orderMode: asc, filters: $filters) {
      edges { node { id name } }
      pageInfo { endCursor hasNextPage globalCount }
    }
  }
`;

export const playbooksQuery = graphql`
  query ExportBundlePlaybooksQuery($search: String, $count: Int!, $cursor: ID) {
    playbooks(search: $search, first: $count, after: $cursor) {
      edges { node { id name } }
      pageInfo { endCursor hasNextPage globalCount }
    }
  }
`;

export const formsQuery = graphql`
  query ExportBundleFormsQuery($search: String, $count: Int!, $cursor: ID) {
    forms(search: $search, first: $count, after: $cursor) {
      edges { node { id name } }
      pageInfo { endCursor hasNextPage globalCount }
    }
  }
`;

export const customViewsQuery = graphql`
  query ExportBundleCustomViewsQuery($search: String, $count: Int!, $cursor: ID) {
    customViews(search: $search, first: $count, after: $cursor) {
      edges { node { id name } }
      pageInfo { endCursor hasNextPage globalCount }
    }
  }
`;

export const ingestionCsvsQuery = graphql`
  query ExportBundleIngestionCsvsQuery($search: String, $count: Int!, $cursor: ID) {
    ingestionCsvs(search: $search, first: $count, after: $cursor) {
      edges { node { id name } }
      pageInfo { endCursor hasNextPage globalCount }
    }
  }
`;

export const ingestionJsonsQuery = graphql`
  query ExportBundleIngestionJsonsQuery($search: String, $count: Int!, $cursor: ID) {
    ingestionJsons(search: $search, first: $count, after: $cursor) {
      edges { node { id name } }
      pageInfo { endCursor hasNextPage globalCount }
    }
  }
`;

export const ingestionRsssQuery = graphql`
  query ExportBundleIngestionRsssQuery($search: String, $count: Int!, $cursor: ID) {
    ingestionRsss(search: $search, first: $count, after: $cursor) {
      edges { node { id name } }
      pageInfo { endCursor hasNextPage globalCount }
    }
  }
`;

export const ingestionTaxiisQuery = graphql`
  query ExportBundleIngestionTaxiisQuery($search: String, $count: Int!, $cursor: ID) {
    ingestionTaxiis(search: $search, first: $count, after: $cursor) {
      edges { node { id name } }
      pageInfo { endCursor hasNextPage globalCount }
    }
  }
`;

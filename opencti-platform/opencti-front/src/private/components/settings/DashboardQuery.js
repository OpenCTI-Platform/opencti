import graphql from 'babel-plugin-relay/macro';

// Risk Query

// eslint-disable-next-line import/prefer-default-export
export const dashboardQueryRiskTimeSeries = graphql`
  query DashboardQueryRiskTimeSeriesQuery(
    $type: String
    $field: String!
    $match: [String]
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: Interval!
  ) {
    risksTimeSeries(
      type: $type
      match: $match
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      interval: $interval
    ) {
      date
      label
      value
    }
  }
`;

// eslint-disable-next-line import/prefer-default-export
export const dashboardQueryRisksDistribution = graphql`
  query DashboardQueryRisksDistributionQuery(
    $type: String
    $match: [String]
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $limit: Int
  ) {
    risksDistribution(
      type: $type
      match: $match
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      limit: $limit
    ) {
      label
      value
    }
  }
`;

// eslint-disable-next-line import/prefer-default-export
export const dashboardQueryRisksBarDistribution = graphql`
  query DashboardQueryRisksBarDistributionQuery(
    $type: String
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $limit: Int
  ) {
    risksDistribution(
      type: $type
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      limit: $limit
    ) {
      label
      value
      entity {
        ... on Risk {
          id
          created
          name
          first_seen
          last_seen
          risk_level
          occurrences
          deadline
        }
      }
    }
  }
`;

// eslint-disable-next-line import/prefer-default-export
export const dashboardQueryRisksListDistribution = graphql`
  query DashboardQueryRisksListDistributionQuery(
    $type: String
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $limit: Int
  ) {
    risksDistribution(
      type: $type
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      limit: $limit
    ) {
      label
      value
      entity {
        ... on Risk {
          id
          created
          name
          first_seen
          last_seen
          risk_level
          occurrences
          deadline
        }
      }
    }
  }
`;

// eslint-disable-next-line import/prefer-default-export
export const dashboardQueryRisksCount = graphql`
  query DashboardQueryRisksCountQuery(
    $type: String
    $field: String!
    $match: [String]
    $operation: StatsOperation
    $endDate: DateTime!
  ) {
    risksCount(
      type: $type
      match: $match
      field: $field
      operation: $operation
      endDate: $endDate
    ) {
      total
      count
    }
  }
`;

// Asset Query

// eslint-disable-next-line import/prefer-default-export
export const dashboardQueryAssetsTimeSeries = graphql`
  query DashboardQueryAssetsTimeSeriesQuery(
    $type: String
    $field: String!
    $match: [String]
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: Interval!
  ) {
    assetsTimeSeries(
      type: $type
      match: $match
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      interval: $interval
    ) {
      date
      label
      value
    }
  }
`;

// eslint-disable-next-line import/prefer-default-export
export const dashboardQueryAssetsCount = graphql`
  query DashboardQueryAssetsCountQuery(
    $type: String
    $field: String!
    $match: [String]
    $operation: StatsOperation
    $endDate: DateTime
  ) {
    assetsCount(
      type: $type
      match: $match
      field: $field
      operation: $operation
      endDate: $endDate
    ) {
      total
      count
    }
  }
`;

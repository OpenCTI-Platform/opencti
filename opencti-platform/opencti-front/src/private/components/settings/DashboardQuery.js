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
  ) {
    risksDistribution(
      type: $type
      match: $match
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
    ) {
      label
      value
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

import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { FilterGroup as RelayFilterGroup, Filter as RelayFilter, MetricsMonthlyQuery, MetricsMonthlyQuery$variables } from './__generated__/MetricsMonthlyQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetDifference from '../../../../components/dashboard/WidgetDifference';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import { useFormatter } from '../../../../components/i18n';
import { metricsGraphqlQueryUser } from './metrics.d';

export const mauDataQuery = graphql`
  query MetricsMonthlyQuery (
    $distributionParameters: [auditsDistributionParameters]
  ) {
    auditsMultiDistribution(
      dateAttribute: ""
      operation: count
      types: ["History", "Activity"]
      distributionParameters: $distributionParameters
    ) {
      data {
        label
      }
    }
  }
`;

interface MetricsMonthlyComponentProps {
  queryRef: PreloadedQuery<MetricsMonthlyQuery>
}

interface MetricsMonthlyProps {
  variant: string,
  endDate: string | null,
  startDate: string | null,
  parameters: {
    title?: string;
  }
  dataSelection?: {
    filters?: unknown;
  }[];
}

function convertToRelayFilterGroup(input?: any): RelayFilterGroup | undefined {
  if (!input) return undefined;
  return {
    mode: input.mode,
    filters: input.filters.map((f: { key: any; values: any; }) => ({
      ...f,
      key: Array.isArray(f.key) ? f.key : [f.key],
      values: f.values,
    })) as readonly RelayFilter[],
    filterGroups: input.filterGroups ?? [],
  };
}

const MetricsMonthlyComponent: FunctionComponent<MetricsMonthlyComponentProps> = ({
  queryRef,
}) => {
  const data = usePreloadedQuery<MetricsMonthlyQuery>(
    mauDataQuery,
    queryRef,
  );

  if (data) {
    // Previous period users, filtered to non-null users
    const previousData = data.auditsMultiDistribution
      ?.[0]?.data?.filter((user: metricsGraphqlQueryUser) => !!user) ?? [];
    // Current period users, filtered to non-null users
    const currentData = data.auditsMultiDistribution
      ?.[1]?.data?.filter((user: metricsGraphqlQueryUser) => !!user) ?? [];
    const previousCount = new Set(previousData.map((user: metricsGraphqlQueryUser) => user?.label)).size;
    const currentCount = new Set(currentData.map((user: metricsGraphqlQueryUser) => user?.label)).size;

    return (
      <WidgetDifference
        count={currentCount}
        change={currentCount - previousCount}
        interval="month"
      />
    );
  }
  return <WidgetNoData />;
};

const MetricsMonthly: React.FC<MetricsMonthlyProps> = ({
  parameters,
  variant,
  endDate,
  startDate,
  dataSelection,
}) => {
  const { t_i18n } = useFormatter();
  const height = 300;
  const filters = convertToRelayFilterGroup(dataSelection?.[0]?.filters);

  // Last period consists of two months ago to one month ago
  // Current period consists of one month ago to now
  const now = new Date();
  now.setHours(23, 59, 59, 999);

  const start = startDate ? new Date(startDate) : new Date(now);
  start.setMonth(now.getMonth() - 2);

  const mid = startDate && endDate
    ? new Date(startDate)
    : new Date(now);
  mid.setMonth(now.getMonth() - 1);

  const end = endDate ? new Date(endDate) : now;

  // Get the user logins for last month and this current month
  const distributionParameters: MetricsMonthlyQuery$variables['distributionParameters'] = [
    {
      field: 'user_id',
      startDate: start.toISOString(),
      endDate: mid.toISOString(),
      filters,
    },
    {
      field: 'user_id',
      startDate: mid.toISOString(),
      endDate: end.toISOString(),
      filters,
    },
  ];

  const queryRef = useQueryLoading<MetricsMonthlyQuery>(
    mauDataQuery,
    { distributionParameters },
  );

  return (
    <WidgetContainer
      height={height}
      title={t_i18n(parameters?.title?.trim()) ?? t_i18n('Monthly activity count')}
      variant={variant}
    >
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <MetricsMonthlyComponent queryRef={queryRef} />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};

export default MetricsMonthly;

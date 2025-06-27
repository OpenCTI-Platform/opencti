import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { FilterGroup, MetricsMonthlyQuery, MetricsMonthlyQuery$variables } from './__generated__/MetricsMonthlyQuery.graphql';
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
  parameters: {
    title?: string;
  }
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
}) => {
  const { t_i18n } = useFormatter();
  const height = 300;

  // Last period consists of two months ago to one month ago
  // Current period consists of one month ago to now
  const now = new Date();
  now.setHours(23, 59, 59, 999);
  const lastPeriodStartDate = new Date(now);
  const lastPeriodEndDate = new Date(now);
  lastPeriodStartDate.setMonth(now.getMonth() - 2);
  lastPeriodEndDate.setMonth(now.getMonth() - 1);

  const filters: FilterGroup = {
    mode: 'and',
    filters: [
      {
        key: ['event_scope'],
        values: ['search', 'analyze', 'enrich', 'import', 'export', 'read', 'create', 'delete', 'download', 'disseminate', 'update'],
      },
    ],
    filterGroups: [],
  };

  // Get the user logins for last month and this current month
  const distributionParameters: MetricsMonthlyQuery$variables['distributionParameters'] = [
    {
      field: 'user_id',
      startDate: lastPeriodStartDate.toISOString(),
      endDate: lastPeriodEndDate.toISOString(),
      filters,
    },
    {
      field: 'user_id',
      startDate: lastPeriodEndDate.toISOString(),
      endDate: now.toISOString(),
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

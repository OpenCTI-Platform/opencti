import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import WidgetDifference from '../../../../components/dashboard/WidgetDifference';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { FilterGroup as RelayFilterGroup, Filter as RelayFilter, MetricsWeeklyQuery } from './__generated__/MetricsWeeklyQuery.graphql';
import { metricsGraphqlQueryUser } from './metrics.d';

export const wauDataQuery = graphql`
  query MetricsWeeklyQuery (
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

interface MetricsWeeklyComponentProps {
  queryRef: PreloadedQuery<MetricsWeeklyQuery>
}

interface MetricsWeeklyProps {
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

const MetricsWeeklyComponent: FunctionComponent<MetricsWeeklyComponentProps> = ({
  queryRef,
}) => {
  const data = usePreloadedQuery<MetricsWeeklyQuery>(
    wauDataQuery,
    queryRef,
  ); if (data) {
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
        interval="week"
      />
    );
  }
  return <WidgetNoData />;
};

const MetricsWeekly: React.FC<MetricsWeeklyProps> = ({
  parameters,
  variant,
  endDate,
  startDate,
  dataSelection,
}) => {
  const { t_i18n } = useFormatter();
  const height = 300;
  const filters = convertToRelayFilterGroup(dataSelection?.[0]?.filters);

  let start = startDate ? new Date(startDate) : null;
  let end = endDate ? new Date(endDate) : null;

  // Current period consists of most recent Monday to now
  // Last period is two Mondays ago to the most recent Monday
  // This is so the number widget aligns with the WAU graph
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const dayOfWeek = today.getDay();
  const diffToMonday = dayOfWeek === 0 ? 6 : dayOfWeek - 1;

  const thisMonday = new Date(today);
  thisMonday.setDate(today.getDate() - diffToMonday);

  const now = new Date();
  now.setHours(23, 59, 59, 999);

  if (!start || !end) {
    const lastMonday = new Date(thisMonday);
    lastMonday.setDate(thisMonday.getDate() - 7);
    start = lastMonday;
    end = now;
  }

  const mid = new Date(start);
  mid.setDate(mid.getDate() + 7);

  // Get the user logins for last month and this current month
  const distributionParameters = [
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

  const queryRef = useQueryLoading<MetricsWeeklyQuery>(
    wauDataQuery,
    { distributionParameters },
  );

  return (
    <WidgetContainer
      height={height}
      title={t_i18n(parameters?.title?.trim()) ?? t_i18n('Weekly activity count')}
      variant={variant}
    >
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <MetricsWeeklyComponent queryRef={queryRef} />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};

export default MetricsWeekly;

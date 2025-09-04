import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import WidgetDifference from '../../../../components/dashboard/WidgetDifference';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { FilterGroup as RelayFilterGroup, MetricsUniqueWeeklyQuery, MetricsUniqueWeeklyQuery$variables } from './__generated__/MetricsUniqueWeeklyQuery.graphql';
import { MetricsUniqueMonthlyQuery, MetricsUniqueMonthlyQuery$variables } from './__generated__/MetricsUniqueMonthlyQuery.graphql';
import { MetricsGraphqlQueryUser } from './metrics.d';

type TimeInterval = 'week' | 'month';

export const wauDataQuery = graphql`
  query MetricsUniqueWeeklyQuery (
    $distributionParameters: [AuditsDistributionParameters]
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

export const mauDataQuery = graphql`
  query MetricsUniqueMonthlyQuery (
    $distributionParameters: [AuditsDistributionParameters]
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

interface MetricsUniqueComponentProps {
  queryRef: PreloadedQuery<MetricsUniqueWeeklyQuery> | PreloadedQuery<MetricsUniqueMonthlyQuery>;
  interval: TimeInterval;
}

interface MetricsUniqueProps {
  variant: string;
  endDate: string | null;
  startDate: string | null;
  interval: TimeInterval;
  parameters: {
    title?: string;
  };
  dataSelection?: {
    filters?: unknown;
  }[];
}

type InputRelayFilter = {
  key: string | string[];
  values: string[];
};

type InputRelayFilterGroup = {
  mode: 'and' | 'or';
  filters: InputRelayFilter[];
  filterGroups?: InputRelayFilterGroup[];
};

function convertToRelayFilterGroup(input?: InputRelayFilterGroup): RelayFilterGroup | undefined {
  if (!input) return undefined;
  return {
    mode: input.mode,
    filters: input.filters?.map((f) => ({
      ...f,
      key: Array.isArray(f.key) ? f.key : [f.key],
      values: f.values,
    })),
    filterGroups: input.filterGroups
      ?.map(convertToRelayFilterGroup)
      .filter((g): g is RelayFilterGroup => g !== undefined) ?? [],
  };
}

const MetricsUniqueComponent: FunctionComponent<MetricsUniqueComponentProps> = ({
  queryRef,
  interval,
}) => {
  // Use appropriate query based on interval
  const data = interval === 'week'
    ? usePreloadedQuery<MetricsUniqueWeeklyQuery>(wauDataQuery, queryRef as PreloadedQuery<MetricsUniqueWeeklyQuery>)
    : usePreloadedQuery<MetricsUniqueMonthlyQuery>(mauDataQuery, queryRef as PreloadedQuery<MetricsUniqueMonthlyQuery>);

  if (data) {
    // Previous period users, filtered to non-null users
    const previousData = data.auditsMultiDistribution
      ?.[0]?.data?.filter((user: MetricsGraphqlQueryUser) => !!user) ?? [];
    // Current period users, filtered to non-null users
    const currentData = data.auditsMultiDistribution
      ?.[1]?.data?.filter((user: MetricsGraphqlQueryUser) => !!user) ?? [];
    const previousCount = new Set(previousData.map((user: MetricsGraphqlQueryUser) => user?.label)).size;
    const currentCount = new Set(currentData.map((user: MetricsGraphqlQueryUser) => user?.label)).size;

    return (
      <WidgetDifference
        count={currentCount}
        change={currentCount - previousCount}
        interval={interval}
      />
    );
  }
  return <WidgetNoData />;
};

function generateWeeklyDistributionParameters(
  startDate: string | null,
  endDate: string | null,
  filters: RelayFilterGroup | undefined,
): MetricsUniqueWeeklyQuery$variables['distributionParameters'] {
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

  // Get the user logins for last week and this current week
  return [
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
}

function generateMonthlyDistributionParameters(
  startDate: string | null,
  endDate: string | null,
  filters: RelayFilterGroup | undefined,
): MetricsUniqueMonthlyQuery$variables['distributionParameters'] {
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
  return [
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
}

const MetricsUnique: React.FC<MetricsUniqueProps> = ({
  parameters,
  variant,
  endDate,
  startDate,
  interval,
  dataSelection,
}) => {
  const { t_i18n } = useFormatter();
  const height = 300;
  const filters = convertToRelayFilterGroup(
    dataSelection?.[0]?.filters as InputRelayFilterGroup | undefined,
  );

  // Generate distribution parameters based on interval
  const distributionParameters = interval === 'week'
    ? generateWeeklyDistributionParameters(startDate, endDate, filters)
    : generateMonthlyDistributionParameters(startDate, endDate, filters);

  // Use appropriate query based on interval
  const queryRef = interval === 'week'
    ? useQueryLoading<MetricsUniqueWeeklyQuery>(wauDataQuery, { distributionParameters })
    : useQueryLoading<MetricsUniqueMonthlyQuery>(mauDataQuery, { distributionParameters });

  // Generate default title based on interval
  const defaultTitle = interval === 'week'
    ? 'Weekly activity count'
    : 'Monthly activity count';

  return (
    <WidgetContainer
      height={height}
      title={t_i18n(parameters?.title?.trim()) ?? t_i18n(defaultTitle)}
      variant={variant}
    >
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <MetricsUniqueComponent queryRef={queryRef} interval={interval} />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};

export default MetricsUnique;

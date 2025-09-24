import React, { FunctionComponent } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetVerticalBars from '../../../../components/dashboard/WidgetVerticalBars';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { FilterGroup as RelayFilterGroup, MetricsUniqueWeeklyQuery } from './__generated__/MetricsUniqueWeeklyQuery.graphql';
import { MetricsUniqueMonthlyQuery } from './__generated__/MetricsUniqueMonthlyQuery.graphql';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { wauDataQuery, mauDataQuery } from './MetricsUnique';
import { useFormatter } from '../../../../components/i18n';

/**
 * This file exports a Chart widget showing unique user activity over a given
 * time period. Supports both weekly and monthly intervals.
 * Weekly defaults to a 12-week rolling range, monday start-of-week.
 * Monthly defaults to a 6-month rolling range.
 */

type TimeInterval = 'week' | 'month';

type AuditsDistributionParameters = {
  field: string;
  startDate: string;
  endDate: string;
  filters: RelayFilterGroup | null | undefined;
};

interface MetricsChartComponentProps {
  queryRef: PreloadedQuery<MetricsUniqueWeeklyQuery> | PreloadedQuery<MetricsUniqueMonthlyQuery>;
  dateRanges: AuditsDistributionParameters[];
  interval: TimeInterval;
}

interface MetricsChartProps {
  variant: string;
  startDate: string | null;
  endDate: string | null;
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

const MetricsChartComponent: FunctionComponent<MetricsChartComponentProps> = ({
  queryRef,
  dateRanges,
  interval,
}) => {
  const { t_i18n } = useFormatter();

  // Use appropriate query based on interval
  const data = interval === 'week'
    ? usePreloadedQuery<MetricsUniqueWeeklyQuery>(wauDataQuery, queryRef as PreloadedQuery<MetricsUniqueWeeklyQuery>)
    : usePreloadedQuery<MetricsUniqueMonthlyQuery>(mauDataQuery, queryRef as PreloadedQuery<MetricsUniqueMonthlyQuery>);

  if (data.auditsMultiDistribution) {
    // Create the series data for the Chart widget
    const widgetData = data.auditsMultiDistribution.map((selection, i: number) => ({
      x: dateRanges[i].startDate,
      y: selection?.data?.length ?? 0,
    }));

    const seriesName = interval === 'week'
      ? t_i18n('Weekly activity count')
      : t_i18n('Monthly activity count');

    return (
      <WidgetVerticalBars
        series={[{
          name: seriesName,
          data: widgetData,
        }]}
        interval={interval}
        withExport={false}
        readonly={false}
      />
    );
  }
  return <WidgetNoData />;
};

function generateWeeklyParameters(
  startDate: string | null,
  endDate: string | null,
  filters: RelayFilterGroup | undefined,
  weeks = 12,
): AuditsDistributionParameters[] {
  const distributionParameters: AuditsDistributionParameters[] = [];
  const now = new Date();
  now.setHours(23, 59, 59, 999);

  if (startDate && endDate) {
    const start = new Date(startDate);
    const end = new Date(endDate);
    start.setHours(0, 0, 0, 0);
    end.setHours(23, 59, 59, 999);

    const current = new Date(start);
    while (current <= end) {
      const rangeStart = new Date(current);
      const rangeEnd = new Date(current);
      rangeEnd.setDate(rangeEnd.getDate() + 6);
      rangeEnd.setHours(23, 59, 59, 999);

      distributionParameters.push({
        field: 'user_id',
        startDate: rangeStart.toISOString(),
        endDate: rangeEnd.toISOString(),
        filters,
      });

      current.setDate(current.getDate() + 7);
    }
  } else {
    for (let i = weeks; i > 0; i -= 1) {
      const start = new Date(now);
      const end = new Date(now);

      start.setDate(now.getDate() - i * 7 + 1);
      start.setHours(0, 0, 0, 0);

      if (i === 1) {
        end.setHours(23, 59, 59, 999);
      } else {
        end.setDate(now.getDate() - (i - 1) * 7);
        end.setHours(23, 59, 59, 999);
      }

      distributionParameters.push({
        field: 'user_id',
        startDate: start.toISOString(),
        endDate: end.toISOString(),
        filters,
      });
    }
  }

  return distributionParameters;
}

function generateMonthlyParameters(
  startDate: string | null,
  endDate: string | null,
  filters: RelayFilterGroup | undefined,
  months = 6,
): AuditsDistributionParameters[] {
  const distributionParameters: AuditsDistributionParameters[] = [];
  const now = new Date();

  if (startDate && endDate) {
    const start = new Date(startDate);
    const end = new Date(endDate);
    start.setHours(0, 0, 0, 0);
    end.setHours(23, 59, 59, 999);

    const current = new Date(start);
    while (current <= end) {
      const rangeStart = new Date(current);
      const rangeEnd = new Date(current);

      rangeEnd.setMonth(rangeEnd.getMonth() + 1);
      rangeEnd.setDate(0);
      rangeEnd.setHours(23, 59, 59, 999);

      distributionParameters.push({
        field: 'user_id',
        startDate: rangeStart.toISOString(),
        endDate: rangeEnd.toISOString(),
        filters,
      });

      current.setMonth(current.getMonth() + 1);
    }
  } else {
    // Create rolling date ranges for specified number of months
    for (let i = months; i > 0; i -= 1) {
      // Since setMonth modifies in place, create new Dates from `now`
      const start = new Date(now);
      const end = new Date(now);

      // Date range is `i` months ago to `i+1` months ago
      start.setMonth(now.getMonth() - i);
      end.setMonth(now.getMonth() - i + 1);

      distributionParameters.push({
        field: 'user_id',
        startDate: start.toISOString(),
        endDate: end.toISOString(),
        filters,
      });
    }
  }

  return distributionParameters;
}

const MetricsChart: React.FC<MetricsChartProps> = ({
  parameters,
  variant,
  startDate,
  endDate,
  interval,
  dataSelection,
}) => {
  const { t_i18n } = useFormatter();

  const filters = convertToRelayFilterGroup(
    dataSelection?.[0]?.filters as InputRelayFilterGroup | undefined,
  );

  // Generate distribution parameters based on interval
  const distributionParameters = interval === 'week'
    ? generateWeeklyParameters(startDate, endDate, filters)
    : generateMonthlyParameters(startDate, endDate, filters);

  // Use appropriate query based on interval
  const queryRef = interval === 'week'
    ? useQueryLoading<MetricsUniqueWeeklyQuery>(wauDataQuery, { distributionParameters })
    : useQueryLoading<MetricsUniqueMonthlyQuery>(mauDataQuery, { distributionParameters });

  // Generate default title based on interval
  const defaultTitle = interval === 'week'
    ? 'Weekly activity chart'
    : 'Monthly activity chart';

  return (
    <WidgetContainer
      title={t_i18n(parameters?.title?.trim()) || t_i18n(defaultTitle)}
      variant={variant}
    >
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <MetricsChartComponent
            queryRef={queryRef}
            dateRanges={distributionParameters}
            interval={interval}
          />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};

export default MetricsChart;
